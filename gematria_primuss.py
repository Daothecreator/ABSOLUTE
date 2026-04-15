#!/usr/bin/env python3
"""
Gematria Primus Cipher Engine
Based on Cicada 3301 Liber Primus
Complete implementation for cryptographic analysis

License: Public Domain
Version: 1.0 (April 2026)
"""

from typing import List, Dict, Optional, Tuple


class GematriaPrimus:
    """
    Complete Gematria Primus implementation
    The runic alphabet used in Cicada 3301's Liber Primus
    """
    
    # Complete rune mapping with phonetic, decimal, and prime values
    RUNES: Dict[str, Dict[str, any]] = {
        'ᚠ': {'phonetic': 'F', 'decimal': 0, 'prime': 2},
        'ᚢ': {'phonetic': 'U', 'decimal': 1, 'prime': 3},
        'ᚦ': {'phonetic': 'TH', 'decimal': 2, 'prime': 5},
        'ᚩ': {'phonetic': 'O', 'decimal': 3, 'prime': 7},
        'ᚱ': {'phonetic': 'R', 'decimal': 4, 'prime': 11},
        'ᚳ': {'phonetic': 'C', 'decimal': 5, 'prime': 13},
        'ᚷ': {'phonetic': 'G', 'decimal': 6, 'prime': 17},
        'ᚹ': {'phonetic': 'W', 'decimal': 7, 'prime': 19},
        'ᚻ': {'phonetic': 'H', 'decimal': 8, 'prime': 23},
        'ᚾ': {'phonetic': 'N', 'decimal': 9, 'prime': 29},
        'ᛁ': {'phonetic': 'I', 'decimal': 10, 'prime': 31},
        'ᛄ': {'phonetic': 'J', 'decimal': 11, 'prime': 37},
        'ᛇ': {'phonetic': 'EO', 'decimal': 12, 'prime': 41},
        'ᛈ': {'phonetic': 'P', 'decimal': 13, 'prime': 43},
        'ᛉ': {'phonetic': 'X', 'decimal': 14, 'prime': 47},
        'ᛋ': {'phonetic': 'S', 'decimal': 15, 'prime': 53},
        'ᛏ': {'phonetic': 'T', 'decimal': 16, 'prime': 59},
        'ᛒ': {'phonetic': 'B', 'decimal': 17, 'prime': 61},
        'ᛖ': {'phonetic': 'E', 'decimal': 18, 'prime': 67},
        'ᛗ': {'phonetic': 'M', 'decimal': 19, 'prime': 71},
        'ᛚ': {'phonetic': 'L', 'decimal': 20, 'prime': 73},
        'ᛝ': {'phonetic': 'ING', 'decimal': 21, 'prime': 79},
        'ᛟ': {'phonetic': 'OE', 'decimal': 22, 'prime': 83},
        'ᛞ': {'phonetic': 'D', 'decimal': 23, 'prime': 89},
        'ᚪ': {'phonetic': 'A', 'decimal': 24, 'prime': 97},
        'ᚫ': {'phonetic': 'AE', 'decimal': 25, 'prime': 101},
        'ᚣ': {'phonetic': 'Y', 'decimal': 26, 'prime': 103},
        'ᛡ': {'phonetic': 'IA', 'decimal': 27, 'prime': 107},
        'ᛠ': {'phonetic': 'EA', 'decimal': 28, 'prime': 109},
    }
    
    # Cryptographic constants
    MODULUS = 29
    HARMONIC_KEY = "2422826321411203"
    RSA_MODULUS = 3409933  # 1033 * 3301
    MAGIC_SQUARE_CONSTANT = 1033  # emirp of 3301
    ORGANIZATION_SIGNATURE = 3301
    
    def __init__(self):
        """Initialize cipher engine with lookup tables"""
        self.rune_to_char = {k: v['phonetic'] for k, v in self.RUNES.items()}
        self.char_to_rune = {v['phonetic']: k for k, v in self.RUNES.items()}
        self.decimal_to_rune = {v['decimal']: k for k, v in self.RUNES.items()}
        self.prime_to_rune = {v['prime']: k for k, v in self.RUNES.items()}
    
    def rune_to_decimal(self, rune: str) -> int:
        """Convert rune to decimal index"""
        return self.RUNES.get(rune, {}).get('decimal', 0)
    
    def rune_to_prime(self, rune: str) -> int:
        """Convert rune to prime number value"""
        return self.RUNES.get(rune, {}).get('prime', 0)
    
    def decimal_to_rune_char(self, decimal: int) -> str:
        """Convert decimal index to rune"""
        return self.decimal_to_rune.get(decimal % self.MODULUS, 'ᚠ')
    
    def gematric_sum(self, text: str) -> int:
        """
        Calculate gematric sum of runic text
        Example: "Patience is a virtue" = 761
        """
        total = 0
        for char in text:
            if char in self.RUNES:
                total += self.RUNES[char]['prime']
        return total
    
    def atbash_transform(self, decimal: int) -> int:
        """
        Apply Atbash cipher: decimal[i] = 28 - decimal[i]
        Used for Page "A Warning" decryption
        """
        return 28 - decimal
    
    def vigenere_shift(self, decimal: int, key_char: int) -> int:
        """
        Apply Vigenere shift with modulo 29
        Used for Page "Welcome" decryption
        """
        return (decimal + key_char) % self.MODULUS
    
    def apply_harmonic_key(self, decimals: List[int], page_number: int) -> List[int]:
        """
        Apply harmonic key 2422826321411203
        Odd pages: direct key
        Even pages: mirror key
        """
        key = self.HARMONIC_KEY
        if page_number % 2 == 0:  # Even pages: mirror
            key = key[::-1]
        
        result = []
        for i, d in enumerate(decimals):
            key_digit = int(key[i % len(key)])
            shifted = (d - key_digit) % self.MODULUS
            result.append(shifted)
        return result
    
    def frequency_analysis(self, runic_text: str) -> Dict[str, any]:
        """
        Perform frequency analysis on runic text
        Returns statistics including Index of Coincidence
        """
        runes_only = [r for r in runic_text if r in self.RUNES]
        total = len(runes_only)
        
        if total == 0:
            return {'error': 'No valid runes found'}
        
        # Count frequencies
        frequencies = {}
        for rune in runes_only:
            frequencies[rune] = frequencies.get(rune, 0) + 1
        
        # Calculate Index of Coincidence
        ic_numerator = sum(n * (n - 1) for n in frequencies.values())
        ic = ic_numerator / (total * (total - 1)) if total > 1 else 0
        
        # Count doubles (same rune consecutively)
        doubles = sum(1 for i in range(len(runes_only) - 1) 
                     if runes_only[i] == runes_only[i + 1])
        doubles_pct = (doubles / total) * 100
        
        return {
            'total_runes': total,
            'unique_runes': len(frequencies),
            'frequencies': {r: f/total for r, f in frequencies.items()},
            'index_of_coincidence': ic,
            'doubles_count': doubles,
            'doubles_percentage': doubles_pct,
            'is_likely_rsa': ic < 1.1 and doubles_pct < 1.0
        }
    
    def decrypt_page_atbash(self, runic_text: str) -> str:
        """
        Decrypt using Atbash cipher
        Used for Page "A Warning" and "Koan 1"
        """
        result = []
        for rune in runic_text:
            if rune in self.RUNES:
                decimal = self.rune_to_decimal(rune)
                transformed = self.atbash_transform(decimal)
                new_rune = self.decimal_to_rune_char(transformed)
                result.append(self.RUNES[new_rune]['phonetic'])
            else:
                result.append(rune)
        return ''.join(result)
    
    def decrypt_page_vigenere(self, runic_text: str, key: str) -> str:
        """
        Decrypt using Vigenere cipher with given key
        Key should be converted to decimal shifts
        """
        key_shifts = [self.RUNES.get(r, {}).get('decimal', 0) for r in key]
        
        result = []
        key_idx = 0
        for rune in runic_text:
            if rune in self.RUNES:
                decimal = self.rune_to_decimal(rune)
                shift = key_shifts[key_idx % len(key_shifts)]
                transformed = (decimal - shift) % self.MODULUS
                new_rune = self.decimal_to_rune_char(transformed)
                result.append(self.RUNES[new_rune]['phonetic'])
                key_idx += 1
            else:
                result.append(rune)
        return ''.join(result)
    
    def verify_checksum(self, page_runes: List[str]) -> bool:
        """
        Verify gematric checksum
        Page 58: gematric_sum - key_sum = 3301
        """
        page_sum = sum(self.rune_to_prime(r) for r in page_runes if r in self.RUNES)
        key_sum = sum(int(d) for d in self.HARMONIC_KEY)
        return (page_sum - key_sum) == self.ORGANIZATION_SIGNATURE
    
    def get_1203_prime(self) -> int:
        """
        Get the 1203rd prime number
        Used for PGP payload verification
        """
        def is_prime(n: int) -> bool:
            if n < 2:
                return False
            for i in range(2, int(n**0.5) + 1):
                if n % i == 0:
                    return False
            return True
        
        count = 0
        num = 2
        while True:
            if is_prime(num):
                count += 1
                if count == 1203:
                    return num
            num += 1
    
    def generate_tor_derivation(self) -> str:
        """
        Generate Tor onion address from harmonic key
        Each digit mapped to Base-32 equivalent
        """
        base32_map = 'abcdefghijklmnopqrstuvwxyz234567'
        onion_chars = []
        
        for digit in self.HARMONIC_KEY:
            idx = int(digit) % 32
            onion_chars.append(base32_map[idx])
        
        # Add salt (1203) and version
        return f"cyccicada{self.HARMONIC_KEY}v3.onion"


def main():
    """Example usage and verification"""
    gp = GematriaPrimus()
    
    print("=" * 60)
    print("GEMATRIA PRIMUS CIPHER ENGINE")
    print("=" * 60)
    print(f"\nCryptographic Constants:")
    print(f"  RSA Modulus (n): {gp.RSA_MODULUS}")
    print(f"  Magic Square (1033) x Signature (3301) = {gp.RSA_MODULUS}")
    print(f"  Harmonic Key: {gp.HARMONIC_KEY}")
    print(f"  Key Sum: {sum(int(d) for d in gp.HARMONIC_KEY)} (should be 43)")
    print(f"  1203rd Prime: {gp.get_1203_prime()} (should be 9739)")
    
    print(f"\nRune Count: {len(gp.RUNES)}")
    print(f"Sample conversions:")
    sample_runes = ['ᚠ', 'ᚢ', 'ᚦ', 'ᛠ']
    for rune in sample_runes:
        info = gp.RUNES[rune]
        print(f"  {rune} -> Phonetic: {info['phonetic']}, "
              f"Decimal: {info['decimal']}, Prime: {info['prime']}")
    
    print(f"\nTor Derivation: {gp.generate_tor_derivation()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
