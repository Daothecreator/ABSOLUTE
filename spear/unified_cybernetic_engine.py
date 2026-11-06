#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIFIED CYBERNETIC-BIOPHYSICAL EXECUTION MECHANISM (SPEAR / ABSOLUTE-EXECUTION-ENGINE)
======================================================================================
Runnable five-layer planner:

1. Interval arithmetic, compensated summation, GF(256) Reed-Solomon, Merkle proofs
2. Planetary thermodynamic baseline (solar, geothermal, tidal, crustal circularity)
3. Physical-oracle checks: Landauer / Bremermann bounds, fab energy, grid RoCoF,
   continuity and first-law residuals, dual-path scores, BFT quorum
4. Sparse Leontief-Kantorovich planning under nine planetary-boundary ceilings,
   ADMM edge coordination, and a variety comparison
5. Two-tier allocation (open access + Shapley-Scarf top trading cycles), workforce
   roster, Pearl structural causal evaluation, provenance DAG, and a 4-phase
   SQLite ledger

Runtime certificate checks are executed in-process. They are numerical and
combinatorial checks of this program, not a machine-checked proof assistant export.

Requires: numpy, scipy
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import math
import os
import shutil
import sqlite3
import struct
import time
import zlib
from dataclasses import dataclass, field
from decimal import Decimal, getcontext
from fractions import Fraction
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
from scipy import optimize, sparse
from scipy.sparse import linalg as splinalg

getcontext().prec = 50

ENGINE_ID = "ZERO-AZIMUTH-SPEAR-CYBERNETIC-BIOPHYSICAL-ENGINE-V1"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, os.pardir))
DEFAULT_ARTIFACT_DIR = os.path.join(HERE, "artifacts")


def _repo_relative(path: str) -> str:
    absolute = os.path.abspath(path)
    try:
        return os.path.relpath(absolute, REPO_ROOT)
    except ValueError:
        return absolute


@dataclass(frozen=True)
class ValidatedInterval:
    """Outward-rounded decimal interval [inf, sup]."""

    inf: Decimal
    sup: Decimal
    ulp_bound: Decimal = field(default=Decimal("1e-48"))

    def __post_init__(self) -> None:
        if self.inf > self.sup:
            raise ValueError(f"Invalid interval: inf ({self.inf}) > sup ({self.sup})")

    @classmethod
    def from_exact(cls, val: Union[int, str, float, Decimal, Fraction]) -> "ValidatedInterval":
        if isinstance(val, Fraction):
            d_val = Decimal(val.numerator) / Decimal(val.denominator)
            eps = Decimal("1e-48")
            return cls(d_val - eps, d_val + eps, eps)
        if isinstance(val, Decimal):
            return cls(val, val, Decimal("0"))
        d_val = Decimal(str(val))
        return cls(d_val, d_val, Decimal("0"))

    @property
    def midpoint(self) -> Decimal:
        return (self.inf + self.sup) / Decimal("2")

    @property
    def radius(self) -> Decimal:
        return (self.sup - self.inf) / Decimal("2")

    def add(self, other: "ValidatedInterval") -> "ValidatedInterval":
        eps = Decimal("1e-48")
        return ValidatedInterval(
            self.inf + other.inf - eps,
            self.sup + other.sup + eps,
            self.ulp_bound + other.ulp_bound + eps,
        )

    def sub(self, other: "ValidatedInterval") -> "ValidatedInterval":
        eps = Decimal("1e-48")
        return ValidatedInterval(
            self.inf - other.sup - eps,
            self.sup - other.inf + eps,
            self.ulp_bound + other.ulp_bound + eps,
        )

    def mul(self, other: "ValidatedInterval") -> "ValidatedInterval":
        eps = Decimal("1e-48")
        products = [
            self.inf * other.inf,
            self.inf * other.sup,
            self.sup * other.inf,
            self.sup * other.sup,
        ]
        return ValidatedInterval(
            min(products) - eps,
            max(products) + eps,
            self.ulp_bound + other.ulp_bound + eps,
        )

    def div(self, other: "ValidatedInterval") -> "ValidatedInterval":
        if other.inf <= Decimal("0") <= other.sup:
            raise ZeroDivisionError("Interval division by an interval that contains zero.")
        eps = Decimal("1e-48")
        quotients = [
            self.inf / other.inf,
            self.inf / other.sup,
            self.sup / other.inf,
            self.sup / other.sup,
        ]
        return ValidatedInterval(
            min(quotients) - eps,
            max(quotients) + eps,
            self.ulp_bound + other.ulp_bound + eps,
        )

    def contains(self, val: Decimal) -> bool:
        return self.inf <= val <= self.sup

    def to_dict(self) -> Dict[str, str]:
        return {
            "inf": f"{self.inf:.12e}",
            "sup": f"{self.sup:.12e}",
            "midpoint": f"{self.midpoint:.12e}",
            "radius": f"{self.radius:.4e}",
        }


def kahan_babushka_neumaier_sum(values: List[float]) -> Tuple[float, float]:
    """Compensated summation. Returns (sum, estimated ulp error bound)."""
    total = 0.0
    compensation = 0.0
    for x in values:
        t = total + x
        if abs(total) >= abs(x):
            compensation += (total - t) + x
        else:
            compensation += (x - t) + total
        total = t
    final_sum = total + compensation
    ulp_bound = len(values) * float(np.finfo(float).eps) * abs(final_sum)
    return final_sum, ulp_bound


class GF256ReedSolomonCodec:
    """GF(2^8) arithmetic with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)."""

    PRIM = 0x11D

    def __init__(self) -> None:
        self.exp = [0] * 512
        self.log = [0] * 256
        x = 1
        for i in range(255):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= self.PRIM
        for i in range(255, 512):
            self.exp[i] = self.exp[i - 255]

    def gf_mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self.exp[self.log[a] + self.log[b]]

    def gf_div(self, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("GF(256) division by zero")
        if a == 0:
            return 0
        return self.exp[(self.log[a] - self.log[b]) % 255]

    def gf_pow(self, a: int, p: int) -> int:
        if p == 0:
            return 1
        if a == 0:
            return 0
        return self.exp[(self.log[a] * p) % 255]

    def gf_inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("GF(256) inverse of zero")
        return self.exp[255 - self.log[a]]

    def compute_syndromes(self, codeword: List[int], n_sym: int) -> List[int]:
        syndromes = []
        for i in range(1, n_sym + 1):
            root = self.exp[i]
            val = 0
            for coef in codeword:
                val = self.gf_mul(val, root) ^ coef
            syndromes.append(val)
        return syndromes

    def encode_block_4sym(self, data_bytes: bytes) -> Tuple[List[int], int]:
        """Systematic 4-symbol RS parity plus a CRC32 of the codeword."""
        generator = [1]
        for i in range(1, 5):
            root = self.exp[i]
            new_g = [0] * (len(generator) + 1)
            for j, val in enumerate(generator):
                new_g[j] ^= val
                new_g[j + 1] ^= self.gf_mul(val, root)
            generator = new_g

        msg = list(data_bytes) + [0, 0, 0, 0]
        for i in range(len(data_bytes)):
            coef = msg[i]
            if coef != 0:
                for j in range(1, len(generator)):
                    msg[i + j] ^= self.gf_mul(generator[j], coef)
        parity = msg[len(data_bytes):]
        codeword = list(data_bytes) + parity
        crc32 = zlib.crc32(bytes(codeword)) & 0xFFFFFFFF
        return codeword, crc32

    def verify_and_correct_single_byte(self, codeword: List[int]) -> Tuple[bytes, bool, int]:
        """
        Repair one symbol. For a single error at index loc,
        S2/S1 = alpha^(n-1-loc) and the magnitude is S1 / alpha^(n-1-loc).
        """
        synd = self.compute_syndromes(codeword, 4)
        if max(synd) == 0:
            return bytes(codeword[:-4]), False, 0
        if synd[0] == 0:
            raise ValueError("Uncorrectable multi-symbol error in telemetry frame")

        ratio = self.gf_div(synd[1], synd[0])
        power = self.log[ratio]
        n = len(codeword)
        idx = n - 1 - power
        if idx < 0 or idx >= n:
            raise ValueError("Error location outside codeword boundary")

        error_mag = self.gf_div(synd[0], self.exp[power])
        repaired = list(codeword)
        repaired[idx] ^= error_mag
        post_synd = self.compute_syndromes(repaired, 4)
        if max(post_synd) != 0:
            raise ValueError("Multi-symbol corruption exceeded single-symbol repair")
        return bytes(repaired[:-4]), True, 1


class MerkleTree:
    """SHA-256 Merkle tree with domain-separated leaf and node prefixes."""

    def __init__(self, leaves: List[bytes]) -> None:
        if not leaves:
            leaves = [b"EMPTY_LEAF"]
        self.leaves = list(leaves)
        self.leaf_hashes = [hashlib.sha256(b"\x00" + leaf).hexdigest() for leaf in self.leaves]
        self.levels: List[List[str]] = [self.leaf_hashes]
        self._build()

    def _build(self) -> None:
        curr = self.leaf_hashes
        while len(curr) > 1:
            nxt = []
            for i in range(0, len(curr), 2):
                left = curr[i]
                right = curr[i + 1] if i + 1 < len(curr) else curr[i]
                combined = hashlib.sha256(
                    b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
                ).hexdigest()
                nxt.append(combined)
            self.levels.append(nxt)
            curr = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        proof: List[Tuple[str, str]] = []
        idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[idx]
            direction = "R" if idx % 2 == 0 else "L"
            proof.append((direction, sibling_hash))
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: bytes, proof: List[Tuple[str, str]], root: str) -> bool:
        curr = hashlib.sha256(b"\x00" + leaf).hexdigest()
        for direction, sibling_hash in proof:
            if direction == "R":
                curr = hashlib.sha256(
                    b"\x01" + bytes.fromhex(curr) + bytes.fromhex(sibling_hash)
                ).hexdigest()
            else:
                curr = hashlib.sha256(
                    b"\x01" + bytes.fromhex(sibling_hash) + bytes.fromhex(curr)
                ).hexdigest()
        return hmac.compare_digest(curr, root)


@dataclass(frozen=True)
class CrustalElementSpec:
    atomic_number: int
    element: str
    symbol: str
    classification: str
    ppm: Fraction
    weight_pct: Fraction
    virgin_extraction_gj_per_tonne: Decimal
    secondary_recycling_gj_per_tonne: Decimal


class PlanetaryThermodynamicBaseline:
    """Solar, geothermal, tidal, and crustal-circularity evaluations."""

    STEFAN_BOLTZMANN_SIGMA = Decimal("5.670374419e-8")
    BOLTZMANN_KB = Decimal("1.380649e-23")
    REDUCED_PLANCK_HBAR = Decimal("1.054571817e-34")
    SPEED_OF_LIGHT_C = Decimal("299792458")
    SOLAR_RADIUS_M = Decimal("6.96e8")
    SOLAR_SURFACE_TEMP_K = Decimal("5778")
    ASTRONOMICAL_UNIT_M = Decimal("1.495978707e11")
    SOLAR_CONSTANT_S0 = Decimal("1361.0")
    SOLAR_IRRADIANCE_PERIHELION = Decimal("1412.0")
    SOLAR_IRRADIANCE_APHELION = Decimal("1321.0")
    EARTH_MEAN_RADIUS_M = Decimal("6.371e6")
    PI = Decimal("3.14159265358979323846264338327950288419716939937510")

    TOA_AVERAGE_FLUX = Decimal("340.25")
    ALBEDO_ATMOS_CLOUDS = Decimal("77.0")
    ALBEDO_SURFACE = Decimal("23.0")
    ABSORBED_SOLAR_RADIATION_ASR = Decimal("240.25")

    HUMAN_CONTINUOUS_DRAW_W = Decimal("1.8e13")
    HUMAN_ANNUAL_CONSUMPTION_J = Decimal("5.76e20")
    TOTAL_FOSSIL_FISSILE_RESERVES_J = Decimal("6.5e22")

    EARTH_INTERNAL_HEAT_J = Decimal("1.0e31")
    GEOTHERMAL_SURFACE_FLUX_W = Decimal("4.7e13")
    GEOTHERMAL_FLUX_UNCERTAINTY_W = Decimal("0.2e13")
    MEAN_LITHOSPHERIC_FLUX_MW_M2 = Decimal("91.6")
    UPPER_10KM_RECOVERABLE_J = Decimal("3.3e25")

    EARTH_MOMENT_OF_INERTIA = Decimal("8.04e37")
    EARTH_ANGULAR_VELOCITY_RAD_S = Decimal("7.292115e-5")
    EARTH_ANGULAR_DECEL_RAD_S2 = Decimal("-4.0e-22")
    LUNAR_RECESSION_MM_YR = Decimal("38.30")
    TOTAL_TIDAL_DISSIPATION_W = Decimal("3.7e12")
    SHALLOW_SEAS_DISSIPATION_W = Decimal("2.7e12")
    ABYSSAL_INTERNAL_WAVES_W = Decimal("1.0e12")

    CRUSTAL_ELEMENTS: List[CrustalElementSpec] = [
        CrustalElementSpec(8, "Oxygen", "O", "Lithophile", Fraction(461000, 1000000), Fraction(4610, 100), Decimal("2.0"), Decimal("0.4")),
        CrustalElementSpec(14, "Silicon", "Si", "Lithophile", Fraction(282000, 1000000), Fraction(2820, 100), Decimal("85.0"), Decimal("12.0")),
        CrustalElementSpec(13, "Aluminum", "Al", "Lithophile", Fraction(82300, 1000000), Fraction(823, 100), Decimal("210.0"), Decimal("10.5")),
        CrustalElementSpec(26, "Iron", "Fe", "Siderophile", Fraction(56300, 1000000), Fraction(563, 100), Decimal("22.0"), Decimal("6.2")),
        CrustalElementSpec(20, "Calcium", "Ca", "Lithophile", Fraction(41500, 1000000), Fraction(415, 100), Decimal("18.0"), Decimal("3.5")),
        CrustalElementSpec(11, "Sodium", "Na", "Lithophile", Fraction(23600, 1000000), Fraction(236, 100), Decimal("35.0"), Decimal("7.0")),
        CrustalElementSpec(12, "Magnesium", "Mg", "Lithophile", Fraction(23300, 1000000), Fraction(233, 100), Decimal("145.0"), Decimal("14.5")),
        CrustalElementSpec(19, "Potassium", "K", "Lithophile", Fraction(20900, 1000000), Fraction(209, 100), Decimal("14.0"), Decimal("3.2")),
        CrustalElementSpec(22, "Titanium", "Ti", "Lithophile", Fraction(5650, 1000000), Fraction(565, 1000), Decimal("400.0"), Decimal("68.0")),
        CrustalElementSpec(1, "Hydrogen", "H", "Atmophile", Fraction(1400, 1000000), Fraction(140, 1000), Decimal("142.0"), Decimal("18.0")),
        CrustalElementSpec(15, "Phosphorus", "P", "Lithophile", Fraction(1050, 1000000), Fraction(105, 1000), Decimal("17.5"), Decimal("2.1")),
        CrustalElementSpec(25, "Manganese", "Mn", "Lithophile", Fraction(950, 1000000), Fraction(95, 1000), Decimal("48.0"), Decimal("11.0")),
        CrustalElementSpec(6, "Carbon", "C", "Atmophile", Fraction(200, 1000000), Fraction(20, 1000), Decimal("30.0"), Decimal("4.5")),
        CrustalElementSpec(29, "Copper", "Cu", "Chalcophile", Fraction(60, 1000000), Fraction(6, 1000), Decimal("58.0"), Decimal("2.9")),
    ]

    @classmethod
    def exact_intercepted_solar_power_w(cls) -> Decimal:
        earth_cross_section = cls.PI * (cls.EARTH_MEAN_RADIUS_M ** 2)
        return earth_cross_section * cls.SOLAR_CONSTANT_S0

    @classmethod
    def solar_power_interval(cls) -> ValidatedInterval:
        radius = ValidatedInterval.from_exact(cls.EARTH_MEAN_RADIUS_M)
        pi_int = ValidatedInterval.from_exact(cls.PI)
        s0_int = ValidatedInterval.from_exact(cls.SOLAR_CONSTANT_S0)
        return pi_int.mul(radius.mul(radius)).mul(s0_int)

    @classmethod
    def evaluate_solar_budget(cls) -> Dict[str, Any]:
        solar_area = Decimal("4") * cls.PI * (cls.SOLAR_RADIUS_M ** 2)
        solar_luminosity_w = cls.STEFAN_BOLTZMANN_SIGMA * solar_area * (cls.SOLAR_SURFACE_TEMP_K ** 4)
        intercepted_power_w = cls.exact_intercepted_solar_power_w()
        hourly_energy_j = intercepted_power_w * Decimal("3600")
        annual_seconds = Decimal("31557600")
        annual_energy_j = intercepted_power_w * annual_seconds
        surplus_ratio = annual_energy_j / cls.HUMAN_ANNUAL_CONSUMPTION_J
        minutes_to_match_human_year = (cls.HUMAN_ANNUAL_CONSUMPTION_J / intercepted_power_w) / Decimal("60")
        days_to_match_all_fossils = (cls.TOTAL_FOSSIL_FISSILE_RESERVES_J / intercepted_power_w) / Decimal("86400")
        return {
            "solar_surface_area_m2": float(solar_area),
            "solar_luminosity_w": float(solar_luminosity_w),
            "earth_cross_section_m2": float(cls.PI * (cls.EARTH_MEAN_RADIUS_M ** 2)),
            "intercepted_continuous_power_w": float(intercepted_power_w),
            "intercepted_continuous_power_w_exact": format(intercepted_power_w, "f"),
            "intercepted_continuous_power_tw": float(intercepted_power_w / Decimal("1e12")),
            "hourly_energy_ej": float(hourly_energy_j / Decimal("1e18")),
            "annual_energy_j": float(annual_energy_j),
            "annual_energy_ej": float(annual_energy_j / Decimal("1e18")),
            "human_annual_consumption_ej": float(cls.HUMAN_ANNUAL_CONSUMPTION_J / Decimal("1e18")),
            "solar_to_human_surplus_ratio": float(surplus_ratio),
            "minutes_of_sun_for_full_human_year": float(minutes_to_match_human_year),
            "days_of_sun_for_all_fossil_uranium_reserves": float(days_to_match_all_fossils),
            "one_percent_capture_multiple_of_demand": float(
                (intercepted_power_w * Decimal("0.01")) / cls.HUMAN_CONTINUOUS_DRAW_W
            ),
        }

    @classmethod
    def evaluate_geothermal_and_millimeter_wave_drilling(cls, target_depth_km: float = 20.0) -> Dict[str, Any]:
        longevity_years = cls.EARTH_INTERNAL_HEAT_J / cls.HUMAN_ANNUAL_CONSUMPTION_J
        annual_flux_min_ej = (
            (cls.GEOTHERMAL_SURFACE_FLUX_W - cls.GEOTHERMAL_FLUX_UNCERTAINTY_W)
            * Decimal("31557600")
            / Decimal("1e18")
        )
        annual_flux_max_ej = (
            (cls.GEOTHERMAL_SURFACE_FLUX_W + cls.GEOTHERMAL_FLUX_UNCERTAINTY_W)
            * Decimal("31557600")
            / Decimal("1e18")
        )
        depth_d = Decimal(str(target_depth_km))
        temp_low_c = Decimal("15.0") + Decimal("24.25") * depth_d
        temp_high_c = Decimal("15.0") + Decimal("27.5") * depth_d
        gyrotron_power_w = Decimal("1.0e6")
        borehole_area_m2 = cls.PI * (Decimal("0.11") ** 2)
        rock_volume_m3 = borehole_area_m2 * (depth_d * Decimal("1000"))
        granite_ablation_enthalpy_j_m3 = Decimal("5.2e9")
        waveguide_coupling_efficiency = Decimal("0.72")
        ablation_time_days = (rock_volume_m3 * granite_ablation_enthalpy_j_m3) / (
            gyrotron_power_w * waveguide_coupling_efficiency * Decimal("86400")
        )
        return {
            "total_internal_heat_j": float(cls.EARTH_INTERNAL_HEAT_J),
            "civilizational_longevity_years": float(longevity_years),
            "continuous_flux_tw": float(cls.GEOTHERMAL_SURFACE_FLUX_W / Decimal("1e12")),
            "annual_lithospheric_emission_ej_range": [float(annual_flux_min_ej), float(annual_flux_max_ej)],
            "upper_10km_recoverable_j": float(cls.UPPER_10KM_RECOVERABLE_J),
            "target_borehole_depth_km": target_depth_km,
            "basement_rock_temperature_c_range": [float(temp_low_c), float(temp_high_c)],
            "gyrotron_1mw_ablation_days_to_target": float(ablation_time_days),
            "project_obsidian_initial_mw": 50.0,
            "project_obsidian_expanded_mw": 250.0,
            "land_footprint_reduction_vs_solar_pct": 99.0,
        }

    @classmethod
    def evaluate_tidal_dissipation(cls) -> Dict[str, Any]:
        rotational_ke_j = (
            Decimal("0.5") * cls.EARTH_MOMENT_OF_INERTIA * (cls.EARTH_ANGULAR_VELOCITY_RAD_S ** 2)
        )
        dE_dt_w = (
            cls.EARTH_MOMENT_OF_INERTIA
            * cls.EARTH_ANGULAR_VELOCITY_RAD_S
            * cls.EARTH_ANGULAR_DECEL_RAD_S2
        )
        return {
            "rotational_kinetic_energy_j": float(rotational_ke_j),
            "axial_rotational_power_extracted_tw": float(abs(dE_dt_w) / Decimal("1e12")),
            "total_astronomical_tidal_dissipation_tw": float(cls.TOTAL_TIDAL_DISSIPATION_W / Decimal("1e12")),
            "shallow_marginal_seas_dissipation_tw": float(cls.SHALLOW_SEAS_DISSIPATION_W / Decimal("1e12")),
            "abyssal_internal_wave_dissipation_tw": float(cls.ABYSSAL_INTERNAL_WAVES_W / Decimal("1e12")),
            "lunar_recession_mm_per_year": float(cls.LUNAR_RECESSION_MM_YR),
        }

    @classmethod
    def evaluate_entropy_of_mixing_and_circularity(
        cls,
        temperature_k: float = 1200.0,
        molar_fractions: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        gas_constant = 8.31446261815324
        if molar_fractions is None:
            molar_fractions = [0.45, 0.28, 0.10, 0.08, 0.04, 0.03, 0.02]
        fracs = np.array(molar_fractions, dtype=float)
        fracs = fracs / np.sum(fracs)
        delta_s_mix = -gas_constant * float(np.sum(fracs * np.log(np.clip(fracs, 1e-15, 1.0))))
        min_separation_work = temperature_k * delta_s_mix
        element_table = []
        for spec in cls.CRUSTAL_ELEMENTS:
            savings_pct = (
                (spec.virgin_extraction_gj_per_tonne - spec.secondary_recycling_gj_per_tonne)
                / spec.virgin_extraction_gj_per_tonne
                * Decimal("100")
            )
            element_table.append({
                "atomic_number": spec.atomic_number,
                "element": spec.element,
                "symbol": spec.symbol,
                "classification": spec.classification,
                "crustal_ppm": int(spec.ppm * 1000000),
                "crustal_weight_pct": float(spec.weight_pct),
                "virgin_gj_per_tonne": float(spec.virgin_extraction_gj_per_tonne),
                "secondary_recycling_gj_per_tonne": float(spec.secondary_recycling_gj_per_tonne),
                "energy_reduction_pct": float(savings_pct),
            })
        return {
            "entropy_of_mixing_j_per_mol_k": delta_s_mix,
            "reversible_unmixing_work_j_per_mol_at_1200K": min_separation_work,
            "elements": element_table,
        }


@dataclass
class SensorNodeReading:
    node_id: str
    position_m: float
    mass_density_kg_m3: float
    mass_density_prev_kg_m3: float
    mass_flux_kg_m2_s: float
    power_in_mw: float
    power_out_mw: float
    stored_energy_delta_mw: float
    raw_frame_bytes: bytes = field(default=b"")


class SPEARPhysicalOracleEngine:
    """Thermodynamic ceilings, grid RoCoF, frame repair, and conservation audit."""

    def __init__(self, sink_temp_k: float = 293.15) -> None:
        self.sink_temp_k = Decimal(str(sink_temp_k))
        self.rs_codec = GF256ReedSolomonCodec()
        rng = np.random.default_rng(seed=20261027)
        w_pos = rng.normal(0.0, 0.35, size=(8, 6))
        w_neg = rng.normal(0.0, 0.35, size=(8, 6))
        q_mat, _ = np.linalg.qr(np.hstack([w_pos[:, :3], w_neg[:, :3]]))
        self.W_pos = q_mat[:, :3].T
        self.W_neg = q_mat[:, 3:6].T
        self.pos_centroid = np.array([1.0, 0.0, 0.0])
        self.neg_centroid = np.array([0.0, 1.0, 1.0])

    def compute_thermodynamic_computation_bounds(
        self,
        processor_mass_kg: float = 1.0,
        distance_km: float = 10000.0,
    ) -> Dict[str, Any]:
        kb = PlanetaryThermodynamicBaseline.BOLTZMANN_KB
        hbar = PlanetaryThermodynamicBaseline.REDUCED_PLANCK_HBAR
        c = PlanetaryThermodynamicBaseline.SPEED_OF_LIGHT_C
        pi = PlanetaryThermodynamicBaseline.PI
        ln2 = Decimal(2).ln()
        landauer_j_per_bit = kb * self.sink_temp_k * ln2
        mass_d = Decimal(str(processor_mass_kg))
        bremermann_ops_per_sec = (Decimal("2") * mass_d * (c ** 2)) / (pi * hbar)
        light_latency_s = (Decimal("2") * Decimal(str(distance_km)) * Decimal("1000")) / c
        return {
            "heat_sink_temp_k": float(self.sink_temp_k),
            "landauer_min_energy_per_bit_j": float(landauer_j_per_bit),
            "bremermann_margolus_levitin_ops_per_s_kg": float(bremermann_ops_per_sec),
            "speed_of_light_roundtrip_latency_ms": float(light_latency_s * Decimal("1000")),
        }

    def audit_semiconductor_fab_and_grid_stability(
        self,
        euv_scanners_active: int,
        wafers_per_day: int,
        grid_frequency_hz: float,
        synchronous_inertia_gva_s: float,
        power_imbalance_mw: float,
        nominal_freq_hz: float = 50.0,
    ) -> Dict[str, Any]:
        euv_power_mw = euv_scanners_active * 1.2
        daily_wafer_energy_mwh = wafers_per_day * 1.15
        daily_upw_gallons = wafers_per_day * 7000.0
        rocof_hz_per_s = (power_imbalance_mw * nominal_freq_hz) / max(
            2.0 * synchronous_inertia_gva_s * 1000.0,
            1.0,
        )
        freq_safe = 49.8 <= grid_frequency_hz <= 50.2 and abs(rocof_hz_per_s) <= 0.5
        target_rocof = 0.25
        required_inertia_gva_s = max(
            0.0,
            (abs(power_imbalance_mw) * nominal_freq_hz) / (2.0 * target_rocof * 1000.0)
            - synchronous_inertia_gva_s,
        )
        return {
            "euv_continuous_power_mw": euv_power_mw,
            "daily_wafer_energy_mwh": daily_wafer_energy_mwh,
            "daily_ultra_pure_water_gallons": daily_upw_gallons,
            "grid_frequency_hz": grid_frequency_hz,
            "rocof_hz_per_s": rocof_hz_per_s,
            "wafer_integrity_safe": freq_safe,
            "synthetic_inertia_bess_and_condenser_dispatch_gva_s": required_inertia_gva_s,
        }

    def dual_path_anomaly_score(self, feature_vec: np.ndarray) -> Tuple[float, bool]:
        norm = np.linalg.norm(feature_vec)
        x_hat = feature_vec / (norm if norm > 1e-12 else 1.0)
        z_pos = self.W_pos @ x_hat
        z_neg = self.W_neg @ x_hat
        d_pos = float(np.linalg.norm(z_pos - self.pos_centroid))
        d_neg = float(np.linalg.norm(z_neg - self.neg_centroid))
        margin = d_neg - d_pos
        is_anomalous = float(np.max(np.abs(feature_vec[:2]))) > 1e-2 or margin < -0.35
        return margin, is_anomalous

    def validate_sensor_array_and_reconcile(
        self,
        readings: List[SensorNodeReading],
        dt_sec: float = 1.0,
        inject_cosmic_bitflip_on_node: Optional[int] = 1,
    ) -> Dict[str, Any]:
        n = len(readings)
        preimage = [
            (
                r.mass_density_kg_m3,
                r.mass_flux_kg_m2_s,
                r.power_in_mw,
                r.power_out_mw,
                r.stored_energy_delta_mw,
            )
            for r in readings
        ]
        rs_repairs = 0
        for idx, reading in enumerate(readings):
            payload = struct.pack(
                ">ddddd",
                reading.mass_density_kg_m3,
                reading.mass_flux_kg_m2_s,
                reading.power_in_mw,
                reading.power_out_mw,
                reading.stored_energy_delta_mw,
            )
            codeword, _crc = self.rs_codec.encode_block_4sym(payload)
            if inject_cosmic_bitflip_on_node is not None and idx == inject_cosmic_bitflip_on_node:
                codeword[5] ^= 0b01010101
            restored, was_repaired, _count = self.rs_codec.verify_and_correct_single_byte(codeword)
            if was_repaired:
                rs_repairs += 1
            unpacked = struct.unpack(">ddddd", restored)
            reading.mass_density_kg_m3 = unpacked[0]
            reading.mass_flux_kg_m2_s = unpacked[1]
            reading.power_in_mw = unpacked[2]
            reading.power_out_mw = unpacked[3]
            reading.stored_energy_delta_mw = unpacked[4]
            reading.raw_frame_bytes = restored

        frames_match_preimage = all(
            (
                readings[i].mass_density_kg_m3,
                readings[i].mass_flux_kg_m2_s,
                readings[i].power_in_mw,
                readings[i].power_out_mw,
                readings[i].stored_energy_delta_mw,
            )
            == preimage[i]
            for i in range(n)
        )

        isolated_nodes: List[str] = []
        anomalous_nodes: List[str] = []
        continuity_residuals: List[float] = []
        energy_residuals: List[float] = []
        reconciled_fluxes = [readings[i].mass_flux_kg_m2_s for i in range(n)]

        for i in range(n):
            curr = readings[i]
            prev_node = readings[max(0, i - 1)]
            next_node = readings[min(n - 1, i + 1)]
            dx = max(next_node.position_m - prev_node.position_m, 1.0)
            div_j = (next_node.mass_flux_kg_m2_s - prev_node.mass_flux_kg_m2_s) / dx
            drho_dt = (curr.mass_density_kg_m3 - curr.mass_density_prev_kg_m3) / dt_sec
            cont_res = div_j + drho_dt
            energy_res = curr.power_in_mw - curr.power_out_mw - curr.stored_energy_delta_mw
            feat = np.array(
                [
                    cont_res,
                    energy_res,
                    curr.mass_density_kg_m3 / 1000.0,
                    curr.mass_flux_kg_m2_s / 1000.0,
                    curr.power_in_mw / 100.0,
                    curr.power_out_mw / 100.0,
                    div_j,
                    drho_dt,
                ],
                dtype=float,
            )
            _margin, is_anom = self.dual_path_anomaly_score(feat)
            continuity_residuals.append(abs(cont_res))
            energy_residuals.append(abs(energy_res))
            if is_anom:
                anomalous_nodes.append(curr.node_id)
            if abs(energy_res) > 0.05:
                isolated_nodes.append(curr.node_id)

        for i, node_id in enumerate(readings):
            if node_id.node_id not in isolated_nodes:
                continue
            valid_neighbors = [
                readings[j].mass_flux_kg_m2_s
                for j in range(max(0, i - 2), min(n, i + 3))
                if j != i
                and abs(
                    readings[j].power_in_mw
                    - readings[j].power_out_mw
                    - readings[j].stored_energy_delta_mw
                )
                <= 0.05
            ]
            interp_flux = float(np.mean(valid_neighbors)) if valid_neighbors else 0.0
            readings[i].mass_flux_kg_m2_s = interp_flux
            readings[i].power_out_mw = readings[i].power_in_mw - readings[i].stored_energy_delta_mw
            reconciled_fluxes[i] = interp_flux

        post_energy: List[float] = []
        post_continuity: List[float] = []
        for i in range(n):
            curr = readings[i]
            prev_node = readings[max(0, i - 1)]
            next_node = readings[min(n - 1, i + 1)]
            dx = max(next_node.position_m - prev_node.position_m, 1.0)
            div_j = (next_node.mass_flux_kg_m2_s - prev_node.mass_flux_kg_m2_s) / dx
            drho_dt = (curr.mass_density_kg_m3 - curr.mass_density_prev_kg_m3) / dt_sec
            post_continuity.append(abs(div_j + drho_dt))
            post_energy.append(abs(curr.power_in_mw - curr.power_out_mw - curr.stored_energy_delta_mw))

        energy_sum, energy_ulp = kahan_babushka_neumaier_sum(energy_residuals)
        state_leaves = [
            f"{readings[i].node_id}:{reconciled_fluxes[i]:.8f}".encode("utf-8")
            for i in range(n)
        ]
        merkle = MerkleTree(state_leaves)
        proofs_ok = all(
            MerkleTree.verify_proof(state_leaves[i], merkle.get_proof(i), merkle.root)
            for i in range(n)
        )
        f_faulty = len(isolated_nodes)
        bft_quorum_satisfied = n >= (3 * f_faulty + 1)
        return {
            "total_sensor_nodes": n,
            "reed_solomon_cosmic_bitflips_repaired": rs_repairs,
            "frames_match_preimage_after_repair": frames_match_preimage,
            "isolated_compromised_sensors": isolated_nodes,
            "dual_path_anomalous_nodes": anomalous_nodes,
            "bft_quorum_satisfied": bft_quorum_satisfied,
            "bft_merkle_root": merkle.root,
            "merkle_proofs_verified": proofs_ok,
            "reconciled_mass_flux_vector": reconciled_fluxes,
            "max_raw_energy_violation_mw": float(max(energy_residuals)),
            "raw_energy_residual_kahan_sum_mw": energy_sum,
            "raw_energy_residual_ulp_bound_mw": energy_ulp,
            "post_reconciliation_energy_violation_mw": float(max(post_energy)),
            "post_reconciliation_continuity_residual": float(max(post_continuity)),
        }


@dataclass(frozen=True)
class PlanetaryBoundarySpec:
    process_id: str
    name: str
    control_variable: str
    safe_threshold_b_k: float
    pre_transition_metric: float
    unit: str
    is_upper_bound: bool


class CyberneticLeontiefKantorovichEngine:
    """Leontief balance, Kantorovich LP, and ADMM coordination."""

    SECTORS: List[str] = [
        "S01_Solar_PV_and_Thermal_Arrays",
        "S02_Superhot_Petrothermal_Gyrotron_Wells",
        "S03_Tidal_and_Grid_Inertia_Storage_BESS",
        "S04_Secondary_Metallurgy_and_Circular_Refining",
        "S05_Standardized_Modular_Machinery_and_Fasteners",
        "S06_Semiconductor_and_Optical_Compute_Fabrication",
        "S07_Agroecological_Polyculture_and_Vertical_Farms",
        "S08_Municipal_UPW_Desalination_and_ClosedLoop_Water",
        "S09_Electrified_HighSpeed_Rail_and_Maritime_Logistics",
        "S10_CradleToCradle_Modular_Housing_and_Habitat",
        "S11_OpenSource_Pharmacopeia_and_Clinical_Healthcare",
        "S12_Autonomous_Robotics_and_Ecological_Restoration",
    ]

    PLANETARY_BOUNDARIES: List[PlanetaryBoundarySpec] = [
        PlanetaryBoundarySpec("PB1", "Climate Change (Radiative Forcing)", "Top-of-atmosphere radiative forcing", 1.0, 2.97, "W/m^2", True),
        PlanetaryBoundarySpec("PB2", "Biosphere Integrity (HANPP)", "Human appropriation of net primary production", 10.0, 30.0, "% HANPP", True),
        PlanetaryBoundarySpec("PB3", "Biogeochemical Nitrogen Flow", "Industrial/agricultural N fixation", 62.0, 165.0, "Tg N/yr", True),
        PlanetaryBoundarySpec("PB4", "Biogeochemical Phosphorus Flow", "Global P flow to oceans/soils", 11.0, 18.2, "Tg P/yr", True),
        PlanetaryBoundarySpec("PB5", "Novel Chemical Entities", "Non-biodegradable synthetic release above neutralization", 0.0, 50.0, "Relative Index", True),
        PlanetaryBoundarySpec("PB6", "Freshwater Alteration (Blue Water)", "Blue water runoff deviation", 12.9, 22.6, "% deviation", True),
        PlanetaryBoundarySpec("PB7", "Land-System Change (Agricultural Footprint)", "Non-forested land conversion ceiling", 25.0, 41.0, "% land area", True),
        PlanetaryBoundarySpec("PB8", "Ocean Acidification (Aragonite Deficiency)", "3.50 - Omega_arag", 0.64, 0.66, "3.50 - Omega_arag", True),
        PlanetaryBoundarySpec("PB9", "Atmospheric Aerosol Loading", "Interhemispheric AOD difference", 0.10, 0.063, "AOD units", True),
    ]

    def __init__(self) -> None:
        self.n = len(self.SECTORS)
        self.A_sparse = self._build_empirical_technical_matrix()
        self.d_social = np.array(
            [180.0, 140.0, 95.0, 160.0, 150.0, 110.0, 210.0, 190.0, 175.0, 165.0, 200.0, 145.0],
            dtype=float,
        )
        self.c_weights = np.array(
            [1.2, 1.35, 1.15, 1.25, 1.2, 1.3, 1.5, 1.45, 1.25, 1.4, 1.55, 1.4],
            dtype=float,
        )

    def _build_empirical_technical_matrix(self) -> sparse.csr_matrix:
        rows: List[int] = []
        cols: List[int] = []
        vals: List[float] = []
        couplings = [
            (0, 3, 0.08), (0, 5, 0.06), (0, 8, 0.04),
            (1, 3, 0.07), (1, 4, 0.06), (1, 5, 0.04),
            (2, 3, 0.09), (2, 4, 0.05), (2, 5, 0.05),
            (3, 0, 0.11), (3, 1, 0.09), (3, 8, 0.06), (3, 11, 0.04),
            (4, 0, 0.05), (4, 3, 0.14), (4, 5, 0.05), (4, 8, 0.05),
            (5, 0, 0.07), (5, 1, 0.06), (5, 3, 0.05), (5, 7, 0.09),
            (6, 0, 0.04), (6, 7, 0.12), (6, 8, 0.06), (6, 11, 0.05),
            (7, 0, 0.06), (7, 1, 0.05), (7, 4, 0.05),
            (8, 0, 0.09), (8, 1, 0.08), (8, 2, 0.06), (8, 4, 0.07),
            (9, 3, 0.12), (9, 4, 0.09), (9, 8, 0.05),
            (10, 0, 0.04), (10, 5, 0.06), (10, 7, 0.06), (10, 8, 0.04),
            (11, 0, 0.05), (11, 3, 0.08), (11, 4, 0.09), (11, 5, 0.08),
        ]
        for r, c, v in couplings:
            rows.append(r)
            cols.append(c)
            vals.append(v)
        return sparse.csr_matrix((vals, (rows, cols)), shape=(self.n, self.n), dtype=float)

    def solve_leontief_chebyshev_and_gauss_seidel(
        self,
        d_vec: Optional[np.ndarray] = None,
        tol: float = 1e-13,
        max_iter: int = 200,
    ) -> Dict[str, Any]:
        if d_vec is None:
            d_vec = self.d_social
        A = self.A_sparse
        identity = sparse.eye(self.n, format="csr")
        i_minus_a = identity - A
        eigvals = np.linalg.eigvals(A.toarray())
        rho_a = float(np.max(np.abs(eigvals)))
        if rho_a >= 1.0:
            raise ValueError(f"Hawkins-Simon productivity condition violated: rho(A) = {rho_a} >= 1")

        omega = 1.0
        x_prev = d_vec.copy()
        x_cheb = d_vec.copy()
        cheb_iters = 0
        cheb_residual = float("inf")
        for k in range(1, max_iter + 1):
            cheb_iters = k
            if k == 1:
                omega = 1.0
            elif k == 2:
                omega = 2.0 / (2.0 - rho_a ** 2)
            else:
                omega = 1.0 / (1.0 - 0.25 * (rho_a ** 2) * omega)
            richardson = d_vec + A.dot(x_cheb)
            x_next = omega * (richardson - x_prev) + x_prev
            cheb_residual = float(np.linalg.norm(i_minus_a.dot(x_next) - d_vec, ord=np.inf))
            x_prev = x_cheb
            x_cheb = x_next
            if cheb_residual <= tol:
                break

        a_dense = A.toarray()
        x_gs = d_vec.copy()
        gs_iters = 0
        gs_residual = float("inf")
        for k in range(1, max_iter + 1):
            gs_iters = k
            for i in range(self.n):
                sigma = float(np.dot(a_dense[i, :], x_gs) - a_dense[i, i] * x_gs[i])
                denom = 1.0 - a_dense[i, i]
                x_gs[i] = (d_vec[i] + sigma) / denom
            gs_residual = float(np.linalg.norm(i_minus_a.dot(x_gs) - d_vec, ord=np.inf))
            if gs_residual <= tol:
                break

        x_exact = splinalg.spsolve(i_minus_a, d_vec)
        return {
            "spectral_radius_rho_A": rho_a,
            "hawkins_simon_productive": rho_a < 1.0,
            "chebyshev_iterations": cheb_iters,
            "gauss_seidel_iterations": gs_iters,
            "max_l_inf_residual": cheb_residual,
            "gauss_seidel_l_inf_residual": gs_residual,
            "max_discrepancy_vs_direct_lu": float(np.max(np.abs(x_cheb - x_exact))),
            "gauss_seidel_discrepancy_vs_direct_lu": float(np.max(np.abs(x_gs - x_exact))),
            "gross_output_vector_x": [float(v) for v in x_cheb],
            "net_final_allocation_vector_d": [float(v) for v in d_vec],
        }

    def solve_kantorovich_lp_with_planetary_boundaries(self) -> Dict[str, Any]:
        i_minus_a = np.eye(self.n) - self.A_sparse.toarray()
        e_impact = np.array(
            [
                [0.0002, 0.0001, 0.0001, 0.0006, 0.0003, 0.0003, 0.0002, 0.0001, 0.0003, 0.0003, 0.0001, 0.0001],
                [0.0010, 0.0002, 0.0003, 0.0010, 0.0008, 0.0004, 0.0120, 0.0005, 0.0015, 0.0020, 0.0005, 0.0002],
                [0.0000, 0.0000, 0.0000, 0.0020, 0.0010, 0.0010, 0.1400, 0.0020, 0.0010, 0.0010, 0.0030, 0.0010],
                [0.0000, 0.0000, 0.0000, 0.0005, 0.0002, 0.0002, 0.0240, 0.0005, 0.0002, 0.0003, 0.0005, 0.0002],
                [0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000],
                [0.0005, 0.0003, 0.0002, 0.0020, 0.0010, 0.0035, 0.0180, 0.0040, 0.0005, 0.0015, 0.0015, 0.0005],
                [0.0025, 0.0001, 0.0004, 0.0015, 0.0010, 0.0003, 0.0280, 0.0008, 0.0030, 0.0045, 0.0005, 0.0002],
                [0.0001, 0.0001, 0.0001, 0.0003, 0.0002, 0.0001, 0.0002, 0.0001, 0.0002, 0.0002, 0.0001, 0.0001],
                [0.00001, 0.00001, 0.00001, 0.00005, 0.00003, 0.00002, 0.00002, 0.00001, 0.00002, 0.00002, 0.00001, 0.00001],
            ],
            dtype=float,
        )
        b_safe = np.array([pb.safe_threshold_b_k for pb in self.PLANETARY_BOUNDARIES], dtype=float)
        a_ub = np.vstack([-i_minus_a, i_minus_a, e_impact])
        b_ub = np.concatenate([-self.d_social, 1.35 * self.d_social, b_safe])
        res = optimize.linprog(
            c=-self.c_weights,
            A_ub=a_ub,
            b_ub=b_ub,
            bounds=[(0.0, None)] * self.n,
            method="highs",
        )
        if not res.success:
            raise RuntimeError(f"Kantorovich LP failed to converge: {res.message}")

        x_opt = res.x
        achieved_impact = e_impact @ x_opt
        net_output = i_minus_a @ x_opt
        boundary_audit = []
        for idx, pb in enumerate(self.PLANETARY_BOUNDARIES):
            val = float(achieved_impact[idx])
            if pb.process_id == "PB8":
                post_metric = round(3.50 - val, 4)
                safe_disp = ">= 2.86"
            elif pb.process_id == "PB7":
                post_metric = round(100.0 - val, 2)
                safe_disp = ">= 75.0%"
            else:
                post_metric = round(val, 4)
                safe_disp = f"<= {pb.safe_threshold_b_k}"
            usage = float(val / pb.safe_threshold_b_k * 100.0) if pb.safe_threshold_b_k > 0 else 0.0
            boundary_audit.append({
                "id": pb.process_id,
                "process": pb.name,
                "unit": pb.unit,
                "safe_threshold": safe_disp,
                "pre_transition_market_metric": pb.pre_transition_metric,
                "post_transition_cybernetic_metric": post_metric,
                "raw_constraint_value": val,
                "raw_constraint_usage_pct": usage,
                "compliant": bool(val <= pb.safe_threshold_b_k + 1e-9),
            })
        return {
            "status": "OPTIMAL",
            "total_use_value_objective": float(-res.fun),
            "optimal_gross_output_x": [float(v) for v in x_opt],
            "optimal_net_provision_d": [float(v) for v in net_output],
            "planetary_boundaries_audit": boundary_audit,
        }

    def solve_decentralized_admm_and_vsm(self, rho_penalty: float = 2.5, max_iter: int = 120) -> Dict[str, Any]:
        i_minus_a = np.eye(self.n) - self.A_sparse.toarray()
        d_target = 1.15 * self.d_social
        x_min = np.linalg.solve(i_minus_a, self.d_social)
        ata = i_minus_a.T @ i_minus_a + rho_penalty * np.eye(self.n)
        ata_inv = np.linalg.inv(ata)
        atd = i_minus_a.T @ d_target
        x = x_min.copy()
        z = x_min.copy()
        u = np.zeros(self.n, dtype=float)
        primal_res_hist: List[float] = []
        dual_res_hist: List[float] = []
        for _ in range(max_iter):
            x = ata_inv @ (atd + rho_penalty * (z - u))
            z_prev = z.copy()
            z = np.maximum(x + u, x_min)
            u = u + (x - z)
            primal_res_hist.append(float(np.linalg.norm(x - z)))
            dual_res_hist.append(float(np.linalg.norm(rho_penalty * (z - z_prev))))
            if primal_res_hist[-1] < 1e-10 and dual_res_hist[-1] < 1e-10:
                break
        disturbance_variety_bits = 142.0
        regulator_variety_bits = 196.0
        return {
            "admm_converged_iterations": len(primal_res_hist),
            "final_primal_residual": primal_res_hist[-1],
            "final_dual_residual": dual_res_hist[-1],
            "decentralized_edge_output_x": [float(v) for v in z],
            "vsm_variety_engineering": {
                "parameters_are_scenario_inputs": True,
                "disturbance_variety_shannon_bits_V_D": disturbance_variety_bits,
                "controller_variety_shannon_bits_V_R": regulator_variety_bits,
                "ashby_comparison_holds_for_scenario_inputs": regulator_variety_bits >= disturbance_variety_bits,
                "system_2_3_telemetry_latency_ms": 1.25,
            },
        }


class TwoTierAllocationAndSocialEngine:
    """Open-access tier plus Shapley-Scarf top trading cycles and a civic roster."""

    @staticmethod
    def execute_top_trading_cycles(
        agents: List[str],
        initial_endowments: Dict[str, str],
        strict_preferences: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        remaining_agents: Set[str] = set(agents)
        asset_to_owner: Dict[str, str] = {asset: agent for agent, asset in initial_endowments.items()}
        remaining_assets: Set[str] = set(asset_to_owner.keys())
        final_allocation: Dict[str, str] = {}
        rounds_log: List[Dict[str, Any]] = []
        round_num = 0

        while remaining_agents:
            round_num += 1
            next_agent_map: Dict[str, str] = {}
            agent_top_asset: Dict[str, str] = {}
            for ag in sorted(remaining_agents):
                found = False
                for preferred_asset in strict_preferences[ag]:
                    if preferred_asset in remaining_assets:
                        agent_top_asset[ag] = preferred_asset
                        next_agent_map[ag] = asset_to_owner[preferred_asset]
                        found = True
                        break
                if not found:
                    raise RuntimeError(f"Agent {ag} has no remaining acceptable asset")

            visited: Set[str] = set()
            cycles_found: List[List[str]] = []
            for start_ag in sorted(remaining_agents):
                if start_ag in visited:
                    continue
                path: List[str] = []
                path_set: Set[str] = set()
                curr = start_ag
                while curr not in visited and curr not in path_set:
                    path.append(curr)
                    path_set.add(curr)
                    curr = next_agent_map[curr]
                if curr in path_set:
                    cycle = path[path.index(curr):]
                    cycles_found.append(cycle)
                visited.update(path)

            if not cycles_found:
                raise RuntimeError("TTC graph contained no cycle")

            round_assignments: Dict[str, str] = {}
            for cycle in cycles_found:
                for ag in cycle:
                    assigned_asset = agent_top_asset[ag]
                    final_allocation[ag] = assigned_asset
                    round_assignments[ag] = assigned_asset
                    remaining_agents.remove(ag)
                    remaining_assets.remove(assigned_asset)
                    asset_to_owner.pop(assigned_asset, None)

            rounds_log.append({
                "round": round_num,
                "cycles": cycles_found,
                "assigned": round_assignments,
            })

        individually_rational = True
        for ag in agents:
            init_rank = strict_preferences[ag].index(initial_endowments[ag])
            final_rank = strict_preferences[ag].index(final_allocation[ag])
            if final_rank > init_rank:
                individually_rational = False

        return {
            "total_agents": len(agents),
            "rounds_to_clear": round_num,
            "final_allocation": final_allocation,
            "rounds_trace": rounds_log,
            "individually_rational": individually_rational,
            "pareto_efficient": _allocation_is_pareto(agents, final_allocation, strict_preferences),
            "strict_core_stable": _allocation_in_strict_core(
                agents, initial_endowments, strict_preferences, final_allocation
            ),
        }

    @staticmethod
    def verify_ttc_strategy_proofness(
        agents: List[str],
        initial_endowments: Dict[str, str],
        true_preferences: Dict[str, List[str]],
        test_agent: str,
    ) -> bool:
        truthful_res = TwoTierAllocationAndSocialEngine.execute_top_trading_cycles(
            agents, initial_endowments, true_preferences
        )
        truthful_asset = truthful_res["final_allocation"][test_agent]
        truthful_rank = true_preferences[test_agent].index(truthful_asset)
        all_assets = true_preferences[test_agent]
        for perm in itertools.permutations(all_assets):
            manipulated_prefs = dict(true_preferences)
            manipulated_prefs[test_agent] = list(perm)
            manip_res = TwoTierAllocationAndSocialEngine.execute_top_trading_cycles(
                agents, initial_endowments, manipulated_prefs
            )
            manip_asset = manip_res["final_allocation"][test_agent]
            manip_true_rank = true_preferences[test_agent].index(manip_asset)
            if manip_true_rank < truthful_rank:
                return False
        return True

    @staticmethod
    def compute_workforce_reallocation_and_civic_roster(
        global_workforce_millions: float = 3500.0,
        residual_hazardous_hours_per_month_millions: float = 4200.0,
    ) -> Dict[str, Any]:
        sector_shares = {
            "Electrical_Power_Grids_SCADA": 0.020,
            "Water_Supply_and_Sanitation": 0.015,
            "Intermodal_Logistics_and_Freight": 0.050,
            "Agroecological_Food_Provision": 0.065,
            "Clinical_Healthcare_and_Pharma": 0.075,
        }
        essential_fraction = sum(sector_shares.values())
        liberated_fraction = 1.0 - essential_fraction
        automated_reduction_factor = 0.20
        net_civic_hours = (
            residual_hazardous_hours_per_month_millions * automated_reduction_factor
        ) / global_workforce_millions
        return {
            "global_active_workforce_millions": global_workforce_millions,
            "essential_lifeline_workforce_pct": round(essential_fraction * 100.0, 2),
            "essential_lifeline_workers_millions": round(global_workforce_millions * essential_fraction, 2),
            "liberated_from_pecuniary_overhead_pct": round(liberated_fraction * 100.0, 2),
            "liberated_workers_for_science_ecology_care_millions": round(
                global_workforce_millions * liberated_fraction, 2
            ),
            "sector_breakdown_pct": {k: round(v * 100.0, 2) for k, v in sector_shares.items()},
            "rotational_civic_roster_hours_per_person_month": round(net_civic_hours, 3),
        }


def _allocation_is_pareto(
    agents: List[str],
    allocation: Dict[str, str],
    preferences: Dict[str, List[str]],
) -> bool:
    for r in range(2, len(agents) + 1):
        for coalition in itertools.combinations(agents, r):
            assets = [allocation[a] for a in coalition]
            for perm in itertools.permutations(assets):
                if list(perm) == assets:
                    continue
                improved = False
                worse = False
                for agent, asset in zip(coalition, perm):
                    new_rank = preferences[agent].index(asset)
                    old_rank = preferences[agent].index(allocation[agent])
                    if new_rank < old_rank:
                        improved = True
                    elif new_rank > old_rank:
                        worse = True
                if improved and not worse:
                    return False
    return True


def _allocation_in_strict_core(
    agents: List[str],
    endowments: Dict[str, str],
    preferences: Dict[str, List[str]],
    allocation: Dict[str, str],
) -> bool:
    for r in range(1, len(agents) + 1):
        for coalition in itertools.combinations(agents, r):
            endowed = [endowments[a] for a in coalition]
            for perm in itertools.permutations(endowed):
                if all(
                    preferences[a].index(house) < preferences[a].index(allocation[a])
                    for a, house in zip(coalition, perm)
                ):
                    return False
    return True


class PearlStructuralCausalEpistemicEngine:
    """Three-layer structural causal evaluation and a content-addressed provenance DAG."""

    def __init__(self) -> None:
        self.provenance_dag: Dict[str, Dict[str, Any]] = {}

    def evaluate_pearl_hierarchy(
        self,
        observed_u: float = 1.0,
        observed_x: float = 0.0,
        observed_z: float = 2.4,
        observed_y: float = -4.4,
        counterfactual_do_x: float = 1.0,
    ) -> Dict[str, Any]:
        p_u1 = 0.75
        e_y_given_x0 = 4.5 * 0.0 - 1.5 * (2.4 * 1.0 - 1.8 * 0.0) - 0.8 * 1.0
        e_y_given_x1 = 4.5 * 1.0 - 1.5 * (2.4 * 0.0 - 1.8 * 1.0) - 0.8 * 0.0

        def e_y_do_x(x_val: float) -> float:
            e_z = 2.4 * p_u1 - 1.8 * x_val
            return 4.5 * x_val - 1.5 * e_z - 0.8 * p_u1

        do_x0 = e_y_do_x(0.0)
        do_x1 = e_y_do_x(1.0)
        eps_z = observed_z - (2.4 * observed_u - 1.8 * observed_x)
        eps_y = observed_y - (4.5 * observed_x - 1.5 * observed_z - 0.8 * observed_u)
        z_cf = 2.4 * observed_u - 1.8 * counterfactual_do_x + eps_z
        y_cf_holding_u = 4.5 * counterfactual_do_x - 1.5 * z_cf - 0.8 * observed_u + eps_y
        z_cf_full = 2.4 * 0.0 - 1.8 * counterfactual_do_x + eps_z
        y_cf_full = 4.5 * counterfactual_do_x - 1.5 * z_cf_full - 0.8 * 0.0 + eps_y
        return {
            "layer_1_association_seeing": {
                "E_Y_given_X0_restricted": round(e_y_given_x0, 4),
                "E_Y_given_X1_open": round(e_y_given_x1, 4),
                "naive_associational_difference": round(e_y_given_x1 - e_y_given_x0, 4),
            },
            "layer_2_intervention_doing": {
                "E_Y_do_X0": round(do_x0, 4),
                "E_Y_do_X1": round(do_x1, 4),
                "true_average_causal_effect_do_X": round(do_x1 - do_x0, 4),
            },
            "layer_3_counterfactual_imagining": {
                "abducted_exogenous_eps_Z": round(eps_z, 6),
                "abducted_exogenous_eps_Y": round(eps_y, 6),
                "counterfactual_Y_do_X1_under_legacy_U": round(y_cf_holding_u, 4),
                "counterfactual_Y_do_X1_U0_post_scarcity": round(y_cf_full, 4),
                "net_cognitive_and_prosocial_gain": round(y_cf_full - observed_y, 4),
            },
        }

    def register_provenance_contribution(
        self,
        artifact_title: str,
        creator_collective: str,
        causal_specification: str,
        parent_hashes: List[str],
    ) -> str:
        for parent in parent_hashes:
            if parent not in self.provenance_dag:
                raise KeyError(f"Broken provenance chain: parent hash {parent} is not registered")
        canonical = json.dumps(
            {
                "title": artifact_title,
                "creator": creator_collective,
                "spec": causal_specification,
                "parents": sorted(parent_hashes),
            },
            sort_keys=True,
        ).encode("utf-8")
        cid = hashlib.sha256(canonical).hexdigest()
        self.provenance_dag[cid] = {
            "cid": cid,
            "title": artifact_title,
            "creator": creator_collective,
            "parents": sorted(parent_hashes),
            "causal_specification": causal_specification,
        }
        return cid


class ChronologicalTransitionOrchestrator:
    """Four-phase ledger persisted through SQLite WAL and copied to the artifact path."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.runtime_db_path = "/tmp/spear_cybernetic_state.sqlite3"
        for suffix in ("", "-wal", "-shm"):
            path = self.runtime_db_path + suffix
            if os.path.exists(path):
                os.remove(path)
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.runtime_db_path)
        self._init_acid_schema()

    def _init_acid_schema(self) -> None:
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=FULL;")
            self.conn.execute("PRAGMA foreign_keys=ON;")
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS spear_transition_ledger (
                    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phase_code TEXT NOT NULL UNIQUE,
                    horizon_label TEXT NOT NULL,
                    digital_substrate_state TEXT NOT NULL,
                    physical_allocation_mode TEXT NOT NULL,
                    web_payload_reduction_pct REAL NOT NULL,
                    recovered_compute_capacity_pct REAL NOT NULL,
                    durable_throughput_reduction_pct REAL NOT NULL,
                    agricultural_land_water_saved_pct REAL NOT NULL,
                    military_emissions_eliminated_pct REAL NOT NULL,
                    grid_rocof_hz_s REAL NOT NULL,
                    state_merkle_root TEXT NOT NULL,
                    committed_at_utc TEXT NOT NULL
                );
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS planetary_boundary_commits (
                    boundary_id TEXT PRIMARY KEY,
                    process_name TEXT NOT NULL,
                    safe_threshold TEXT NOT NULL,
                    pre_transition_val REAL NOT NULL,
                    post_transition_val REAL NOT NULL,
                    compliant INTEGER NOT NULL
                );
                """
            )

    def execute_four_phase_simulation(
        self,
        oracle_report: Dict[str, Any],
        lp_report: Dict[str, Any],
        committed_at_utc: str,
    ) -> List[Dict[str, Any]]:
        phases = [
            {
                "phase_code": "PHASE_1",
                "horizon_label": "Days 0 to 30 (T_0 to T_+30d)",
                "digital_substrate_state": (
                    "Remove advertising intermediaries, spyware payloads, and speculative mining; "
                    "move shared code to content-addressed storage."
                ),
                "physical_allocation_mode": (
                    "Treat power, water, telecom, and freight as open lifelines; draw down retail "
                    "and warehouse buffers; reserve liquid fuel for rail, harvesters, and ambulances."
                ),
                "web_payload_reduction_pct": 70.0,
                "recovered_compute_capacity_pct": 40.0,
                "durable_throughput_reduction_pct": 5.0,
                "agricultural_land_water_saved_pct": 10.0,
                "military_emissions_eliminated_pct": 1.5,
                "grid_rocof_hz_s": 0.18,
            },
            {
                "phase_code": "PHASE_2",
                "horizon_label": "Months 1 to 24 (T_+30d to T_+2y)",
                "digital_substrate_state": (
                    "Replace revenue ledgers with the Leontief-Kantorovich balance and reconcile "
                    "sensor disagreements against continuity and the first law."
                ),
                "physical_allocation_mode": (
                    "Open the logistics telemetry, drop patent locks on interchangeable parts, and "
                    "shift monocultures toward regional polycultures."
                ),
                "web_payload_reduction_pct": 74.0,
                "recovered_compute_capacity_pct": 44.0,
                "durable_throughput_reduction_pct": 28.0,
                "agricultural_land_water_saved_pct": 30.0,
                "military_emissions_eliminated_pct": 3.2,
                "grid_rocof_hz_s": 0.12,
            },
            {
                "phase_code": "PHASE_3",
                "horizon_label": "Years 2 to 10 (T_+2y to T_+10y)",
                "digital_substrate_state": (
                    "Schedule wafer refreshes inside EUV power and ultrapure-water limits and keep "
                    "the nine planetary-boundary constraints active in the distributed solve."
                ),
                "physical_allocation_mode": (
                    "Extend equipment life, cut durable throughput, and retool military industrial "
                    "capacity toward rail, deep geothermal drilling, and grid storage."
                ),
                "web_payload_reduction_pct": 76.0,
                "recovered_compute_capacity_pct": 46.0,
                "durable_throughput_reduction_pct": 52.0,
                "agricultural_land_water_saved_pct": 32.5,
                "military_emissions_eliminated_pct": 5.5,
                "grid_rocof_hz_s": 0.08,
            },
            {
                "phase_code": "PHASE_4",
                "horizon_label": "Decade 2+ (T_+10y and beyond)",
                "digital_substrate_state": (
                    "Place dense compute next to firm low-carbon power and cold sinks, inside the "
                    "Landauer energy bound, with an open civic telemetry record."
                ),
                "physical_allocation_mode": (
                    "Run a mature commons on solar, deep petrothermal, and tidal supply, with local "
                    "fabrication and survival separated from compulsory paid labor."
                ),
                "web_payload_reduction_pct": 78.0,
                "recovered_compute_capacity_pct": 48.0,
                "durable_throughput_reduction_pct": 55.0,
                "agricultural_land_water_saved_pct": 35.0,
                "military_emissions_eliminated_pct": 5.5,
                "grid_rocof_hz_s": 0.05,
            },
        ]

        committed_phases: List[Dict[str, Any]] = []
        with self.conn:
            self.conn.execute("DELETE FROM spear_transition_ledger;")
            self.conn.execute("DELETE FROM planetary_boundary_commits;")
            for phase in phases:
                leaf_bytes = json.dumps(phase, sort_keys=True).encode("utf-8")
                merkle = MerkleTree([leaf_bytes, oracle_report["bft_merkle_root"].encode("utf-8")])
                self.conn.execute(
                    """
                    INSERT INTO spear_transition_ledger (
                        phase_code, horizon_label, digital_substrate_state, physical_allocation_mode,
                        web_payload_reduction_pct, recovered_compute_capacity_pct,
                        durable_throughput_reduction_pct, agricultural_land_water_saved_pct,
                        military_emissions_eliminated_pct, grid_rocof_hz_s, state_merkle_root, committed_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        phase["phase_code"],
                        phase["horizon_label"],
                        phase["digital_substrate_state"],
                        phase["physical_allocation_mode"],
                        phase["web_payload_reduction_pct"],
                        phase["recovered_compute_capacity_pct"],
                        phase["durable_throughput_reduction_pct"],
                        phase["agricultural_land_water_saved_pct"],
                        phase["military_emissions_eliminated_pct"],
                        phase["grid_rocof_hz_s"],
                        merkle.root,
                        committed_at_utc,
                    ),
                )
                phase_out = dict(phase)
                phase_out["state_merkle_root"] = merkle.root
                phase_out["committed_at_utc"] = committed_at_utc
                committed_phases.append(phase_out)

            for pb in lp_report["planetary_boundaries_audit"]:
                self.conn.execute(
                    """
                    INSERT INTO planetary_boundary_commits (
                        boundary_id, process_name, safe_threshold, pre_transition_val,
                        post_transition_val, compliant
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        pb["id"],
                        pb["process"],
                        str(pb["safe_threshold"]),
                        float(pb["pre_transition_market_metric"]),
                        float(pb["post_transition_cybernetic_metric"]),
                        1 if pb["compliant"] else 0,
                    ),
                )

        self.conn.execute("PRAGMA wal_checkpoint(FULL);")
        self.conn.close()
        shutil.copy2(self.runtime_db_path, self.db_path)
        return committed_phases


def _ledger_counts(db_path: str) -> Tuple[int, int, int]:
    conn = sqlite3.connect(db_path)
    try:
        phases = conn.execute("SELECT COUNT(*) FROM spear_transition_ledger").fetchone()[0]
        boundaries = conn.execute("SELECT COUNT(*) FROM planetary_boundary_commits").fetchone()[0]
        compliant = conn.execute(
            "SELECT COUNT(*) FROM planetary_boundary_commits WHERE compliant = 1"
        ).fetchone()[0]
    finally:
        conn.close()
    return int(phases), int(boundaries), int(compliant)


def _build_certificate(
    solar: Dict[str, Any],
    p_solar_interval: ValidatedInterval,
    exact_intercept: Decimal,
    comp_bounds: Dict[str, Any],
    oracle_report: Dict[str, Any],
    leontief_report: Dict[str, Any],
    lp_report: Dict[str, Any],
    admm_vsm_report: Dict[str, Any],
    ttc_report: Dict[str, Any],
    strategy_proof: bool,
    phase_count: int,
    ledger_counts: Tuple[int, int, int],
    kahan_unit: float,
) -> Dict[str, bool]:
    net = np.array(lp_report["optimal_net_provision_d"], dtype=float)
    demand = np.array(leontief_report["net_final_allocation_vector_d"], dtype=float)
    checks = {
        "solar_interval_contains_exact_intercept": p_solar_interval.contains(exact_intercept),
        "solar_surplus_ratio_above_1000": solar["solar_to_human_surplus_ratio"] > 1000.0,
        "landauer_energy_positive": comp_bounds["landauer_min_energy_per_bit_j"] > 0.0,
        "bremermann_ops_positive": comp_bounds["bremermann_margolus_levitin_ops_per_s_kg"] > 0.0,
        "reed_solomon_repaired_one_symbol": oracle_report["reed_solomon_cosmic_bitflips_repaired"] == 1,
        "frames_match_preimage_after_repair": oracle_report["frames_match_preimage_after_repair"],
        "oxidized_sensor_isolated": oracle_report["isolated_compromised_sensors"] == ["SCADA_NODE_04_OXIDIZED"],
        "oxidized_sensor_flagged_by_dual_path": "SCADA_NODE_04_OXIDIZED" in oracle_report["dual_path_anomalous_nodes"],
        "bft_quorum_satisfied": oracle_report["bft_quorum_satisfied"],
        "merkle_proofs_verified": oracle_report["merkle_proofs_verified"],
        "post_reconciliation_energy_closed": oracle_report["post_reconciliation_energy_violation_mw"] <= 1e-9,
        "hawkins_simon_productive": leontief_report["hawkins_simon_productive"],
        "chebyshev_matches_lu": leontief_report["max_discrepancy_vs_direct_lu"] < 1e-9,
        "gauss_seidel_matches_lu": leontief_report["gauss_seidel_discrepancy_vs_direct_lu"] < 1e-9,
        "leontief_residual_small": leontief_report["max_l_inf_residual"] <= 1e-12,
        "all_planetary_boundaries_compliant": all(
            row["compliant"] for row in lp_report["planetary_boundaries_audit"]
        ),
        "net_provision_covers_social_demand": bool(np.all(net + 1e-6 >= demand)),
        "net_provision_within_abundance_cap": bool(np.all(net <= 1.35 * demand + 1e-6)),
        "admm_primal_residual_small": admm_vsm_report["final_primal_residual"] < 1e-8,
        "admm_dual_residual_small": admm_vsm_report["final_dual_residual"] < 1e-8,
        "ashby_variety_inequality": admm_vsm_report["vsm_variety_engineering"][
            "ashby_comparison_holds_for_scenario_inputs"
        ],
        "ttc_individually_rational": ttc_report["individually_rational"],
        "ttc_pareto_efficient": ttc_report["pareto_efficient"],
        "ttc_strict_core_stable": ttc_report["strict_core_stable"],
        "ttc_strategy_proof_agent_a1": strategy_proof,
        "four_phases_committed": phase_count == 4,
        "ledger_phase_rows": ledger_counts[0] == 4,
        "ledger_boundary_rows": ledger_counts[1] == 9 and ledger_counts[2] == 9,
        "kahan_recovers_lost_unit": abs(kahan_unit - 1.0) < 1e-8,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise AssertionError("Invariant certificate failed: " + ", ".join(failed))
    return checks


def run_unified_mechanism(
    db_path: Optional[str] = None,
    json_out_path: Optional[str] = None,
    committed_at_utc: Optional[str] = None,
) -> Dict[str, Any]:
    if db_path is None:
        db_path = os.path.join(DEFAULT_ARTIFACT_DIR, "spear_cybernetic_state.sqlite3")
    if json_out_path is None:
        json_out_path = os.path.join(DEFAULT_ARTIFACT_DIR, "unified_execution_telemetry.json")
    if committed_at_utc is None:
        committed_at_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    solar = PlanetaryThermodynamicBaseline.evaluate_solar_budget()
    geothermal = PlanetaryThermodynamicBaseline.evaluate_geothermal_and_millimeter_wave_drilling(20.0)
    tidal = PlanetaryThermodynamicBaseline.evaluate_tidal_dissipation()
    circularity = PlanetaryThermodynamicBaseline.evaluate_entropy_of_mixing_and_circularity()
    exact_intercept = PlanetaryThermodynamicBaseline.exact_intercepted_solar_power_w()
    p_solar_interval = PlanetaryThermodynamicBaseline.solar_power_interval()

    oracle_engine = SPEARPhysicalOracleEngine(sink_temp_k=293.15)
    comp_bounds = oracle_engine.compute_thermodynamic_computation_bounds(
        processor_mass_kg=1.0,
        distance_km=10000.0,
    )
    fab_grid = oracle_engine.audit_semiconductor_fab_and_grid_stability(
        euv_scanners_active=85,
        wafers_per_day=4500,
        grid_frequency_hz=50.00,
        synchronous_inertia_gva_s=180.0,
        power_imbalance_mw=650.0,
    )
    sensor_nodes = [
        SensorNodeReading("SCADA_NODE_01", 0.0, 1000.0, 1000.0, 420.0, 85.0, 84.5, 0.5),
        SensorNodeReading("SCADA_NODE_02", 100.0, 1000.0, 1000.0, 420.0, 86.0, 85.5, 0.5),
        SensorNodeReading("SCADA_NODE_03", 200.0, 1000.0, 1000.0, 420.0, 84.0, 83.5, 0.5),
        SensorNodeReading("SCADA_NODE_04_OXIDIZED", 300.0, 1000.0, 1000.0, 985.0, 85.0, 142.0, 0.5),
        SensorNodeReading("SCADA_NODE_05", 400.0, 1000.0, 1000.0, 420.0, 85.5, 85.0, 0.5),
        SensorNodeReading("SCADA_NODE_06", 500.0, 1000.0, 1000.0, 420.0, 84.5, 84.0, 0.5),
        SensorNodeReading("SCADA_NODE_07", 600.0, 1000.0, 1000.0, 420.0, 85.0, 84.5, 0.5),
    ]
    oracle_report = oracle_engine.validate_sensor_array_and_reconcile(
        sensor_nodes,
        dt_sec=1.0,
        inject_cosmic_bitflip_on_node=1,
    )

    planning_engine = CyberneticLeontiefKantorovichEngine()
    leontief_report = planning_engine.solve_leontief_chebyshev_and_gauss_seidel()
    lp_report = planning_engine.solve_kantorovich_lp_with_planetary_boundaries()
    admm_vsm_report = planning_engine.solve_decentralized_admm_and_vsm()

    agents = ["AGENT_A1", "AGENT_A2", "AGENT_A3", "AGENT_A4", "AGENT_A5"]
    endowments = {
        "AGENT_A1": "HABITAT_H1",
        "AGENT_A2": "HABITAT_H2",
        "AGENT_A3": "HABITAT_H3",
        "AGENT_A4": "HABITAT_H4",
        "AGENT_A5": "HABITAT_H5",
    }
    preferences = {
        "AGENT_A1": ["HABITAT_H2", "HABITAT_H3", "HABITAT_H1", "HABITAT_H4", "HABITAT_H5"],
        "AGENT_A2": ["HABITAT_H3", "HABITAT_H1", "HABITAT_H2", "HABITAT_H5", "HABITAT_H4"],
        "AGENT_A3": ["HABITAT_H1", "HABITAT_H2", "HABITAT_H3", "HABITAT_H4", "HABITAT_H5"],
        "AGENT_A4": ["HABITAT_H5", "HABITAT_H4", "HABITAT_H2", "HABITAT_H1", "HABITAT_H3"],
        "AGENT_A5": ["HABITAT_H4", "HABITAT_H1", "HABITAT_H5", "HABITAT_H3", "HABITAT_H2"],
    }
    ttc_report = TwoTierAllocationAndSocialEngine.execute_top_trading_cycles(agents, endowments, preferences)
    strategy_proof = TwoTierAllocationAndSocialEngine.verify_ttc_strategy_proofness(
        agents, endowments, preferences, test_agent="AGENT_A1"
    )
    ttc_report["exhaustive_strategy_proof_check_agent_A1"] = strategy_proof
    workforce_report = TwoTierAllocationAndSocialEngine.compute_workforce_reallocation_and_civic_roster()

    causal_engine = PearlStructuralCausalEpistemicEngine()
    pearl_report = causal_engine.evaluate_pearl_hierarchy()
    root_cid = causal_engine.register_provenance_contribution(
        "Open-Source 1-MW Millimeter-Wave Gyrotron Waveguide Assembly",
        "MIT-Quaise Open Commons Collective",
        "do(Depth = 20km, Temp = 500C) -> Baseload_Steam = 250MW",
        [],
    )
    child_cid = causal_engine.register_provenance_contribution(
        "Standardized Supercritical Turbine and Universal Fastener BOM v4.2",
        "Global Viable System 1 Turbine Guild",
        "do(Modular_Lifespan = 350%_Extension) -> Durable_Throughput_Reduction = 52%",
        [root_cid],
    )

    orchestrator = ChronologicalTransitionOrchestrator(db_path=db_path)
    transition_phases = orchestrator.execute_four_phase_simulation(
        oracle_report,
        lp_report,
        committed_at_utc=committed_at_utc,
    )
    ledger_counts = _ledger_counts(db_path)
    kahan_unit, _kahan_ulp = kahan_babushka_neumaier_sum([1e16, 1.0, -1e16])
    certificate = _build_certificate(
        solar,
        p_solar_interval,
        exact_intercept,
        comp_bounds,
        oracle_report,
        leontief_report,
        lp_report,
        admm_vsm_report,
        ttc_report,
        strategy_proof,
        len(transition_phases),
        ledger_counts,
        kahan_unit,
    )

    full_telemetry = {
        "metadata": {
            "engine_id": ENGINE_ID,
            "axiomatic_standard": "ZERO-AZIMUTH-STABLE-EXACT-NN-AXIOMS",
            "timestamp_utc": committed_at_utc,
            "sqlite_wal_database": _repo_relative(db_path),
            "certificate_meaning": (
                "In-process numerical and combinatorial checks. Not a proof-assistant export."
            ),
        },
        "invariant_certificate": certificate,
        "layer_1_planetary_thermodynamics": {
            "solar_budget": solar,
            "validated_interval_P_solar_watts": p_solar_interval.to_dict(),
            "geothermal_and_gyrotron": geothermal,
            "tidal_dissipation": tidal,
            "crustal_circularity": circularity,
        },
        "layer_2_spear_oracle_and_substrate": {
            "thermodynamic_computation_ceilings": comp_bounds,
            "semiconductor_and_grid_rocof": fab_grid,
            "physical_oracle_and_bft_consensus": oracle_report,
        },
        "layer_3_cybernetic_planning": {
            "sectors": CyberneticLeontiefKantorovichEngine.SECTORS,
            "leontief_iterative_solver": leontief_report,
            "kantorovich_planetary_boundaries_lp": lp_report,
            "decentralized_admm_and_vsm": admm_vsm_report,
        },
        "layer_4_allocation_labor_and_causal_epistemology": {
            "top_trading_cycles_allocation": ttc_report,
            "workforce_and_civic_roster": workforce_report,
            "pearl_3_layer_causal_hierarchy": pearl_report,
            "epistemic_provenance_dag": {
                "root_cid": root_cid,
                "child_cid": child_cid,
                "nodes": causal_engine.provenance_dag,
            },
        },
        "layer_5_chronological_transition_ledger": transition_phases,
    }

    os.makedirs(os.path.dirname(os.path.abspath(json_out_path)), exist_ok=True)
    with open(json_out_path, "w", encoding="utf-8") as handle:
        json.dump(full_telemetry, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return full_telemetry


if __name__ == "__main__":
    telemetry = run_unified_mechanism()
    certificate = telemetry["invariant_certificate"]
    solar = telemetry["layer_1_planetary_thermodynamics"]["solar_budget"]
    lp = telemetry["layer_3_cybernetic_planning"]["kantorovich_planetary_boundaries_lp"]
    summary = {
        "timestamp_utc": telemetry["metadata"]["timestamp_utc"],
        "checks_passed": sum(1 for ok in certificate.values() if ok),
        "checks_total": len(certificate),
        "intercepted_solar_tw": solar["intercepted_continuous_power_tw"],
        "solar_to_human_surplus_ratio": solar["solar_to_human_surplus_ratio"],
        "use_value_objective": lp["total_use_value_objective"],
        "boundaries_compliant": sum(1 for row in lp["planetary_boundaries_audit"] if row["compliant"]),
        "ttc_allocation": telemetry["layer_4_allocation_labor_and_causal_epistemology"][
            "top_trading_cycles_allocation"
        ]["final_allocation"],
        "sqlite": telemetry["metadata"]["sqlite_wal_database"],
    }
    print(json.dumps(summary, indent=2))
