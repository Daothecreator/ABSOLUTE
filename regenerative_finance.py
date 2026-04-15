#!/usr/bin/env python3
"""
Regenerative Finance (ReFi) Toolkit
Economic tools for sustainable and equitable systems

Features:
- Impact measurement for regenerative projects
- Cooperative economy modeling
- Time banking system
- Universal Basic Income simulation

License: MIT
Version: 1.0 (April 2026)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
import json


class ImpactCategory(Enum):
    """Categories of regenerative impact"""
    CARBON = "carbon"
    WATER = "water"
    BIODIVERSITY = "biodiversity"
    SOCIAL = "social"
    ECONOMIC = "economic"


@dataclass
class ImpactMetric:
    """
    Impact measurement for regenerative projects
    
    Tracks progress toward sustainability goals with
    baseline, current, and target values.
    """
    category: str
    baseline: float
    current: float
    target: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def improvement(self) -> float:
        """Calculate percentage improvement from baseline"""
        if self.baseline == 0:
            return 0.0
        return ((self.current - self.baseline) / self.baseline) * 100
    
    @property
    def progress_to_target(self) -> float:
        """Calculate progress toward target (0-100%)"""
        if self.target == self.baseline:
            return 100.0 if self.current >= self.target else 0.0
        progress = ((self.current - self.baseline) / (self.target - self.baseline)) * 100
        return min(100.0, max(0.0, progress))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'category': self.category,
            'baseline': self.baseline,
            'current': self.current,
            'target': self.target,
            'unit': self.unit,
            'improvement': self.improvement,
            'progress_to_target': self.progress_to_target,
            'timestamp': self.timestamp.isoformat()
        }


class RegenerativeProject:
    """
    Track and manage regenerative projects
    
    A regenerative project creates positive impact across
    multiple dimensions: environmental, social, and economic.
    """
    
    def __init__(self, name: str, project_type: str, location: str,
                 description: str = ""):
        """
        Initialize regenerative project
        
        Args:
            name: Project name
            project_type: Type of project (agriculture, energy, etc.)
            location: Geographic location
            description: Project description
        """
        self.name = name
        self.project_type = project_type
        self.location = location
        self.description = description
        self.created_at = datetime.now()
        self.metrics: List[ImpactMetric] = []
        self.stakeholders: List[Dict] = []
        self.funding_sources: List[Dict] = []
        self.milestones: List[Dict] = []
    
    def add_metric(self, metric: ImpactMetric):
        """Add impact metric to project"""
        self.metrics.append(metric)
    
    def update_metric(self, category: str, new_value: float):
        """Update existing metric with new current value"""
        for metric in self.metrics:
            if metric.category == category:
                metric.current = new_value
                metric.timestamp = datetime.now()
                return True
        return False
    
    def add_stakeholder(self, name: str, role: str, contribution: float = 0):
        """Add project stakeholder"""
        self.stakeholders.append({
            'name': name,
            'role': role,
            'contribution': contribution,
            'joined': datetime.now()
        })
    
    def add_funding(self, source: str, amount: float, currency: str = 'USD'):
        """Add funding source"""
        self.funding_sources.append({
            'source': source,
            'amount': amount,
            'currency': currency,
            'date': datetime.now()
        })
    
    def add_milestone(self, description: str, target_date: datetime,
                      completed: bool = False):
        """Add project milestone"""
        self.milestones.append({
            'description': description,
            'target_date': target_date,
            'completed': completed,
            'completed_date': None
        })
    
    def get_impact_score(self) -> float:
        """Calculate overall impact score (average improvement)"""
        if not self.metrics:
            return 0.0
        return sum(m.improvement for m in self.metrics) / len(self.metrics)
    
    def get_category_breakdown(self) -> Dict[str, float]:
        """Get impact breakdown by category"""
        breakdown = {}
        for metric in self.metrics:
            breakdown[metric.category] = metric.improvement
        return breakdown
    
    def generate_report(self) -> Dict:
        """Generate comprehensive impact report"""
        return {
            'project_name': self.name,
            'type': self.project_type,
            'location': self.location,
            'description': self.description,
            'age_days': (datetime.now() - self.created_at).days,
            'impact_score': self.get_impact_score(),
            'category_breakdown': self.get_category_breakdown(),
            'metrics': [m.to_dict() for m in self.metrics],
            'stakeholders': len(self.stakeholders),
            'total_funding': sum(f['amount'] for f in self.funding_sources),
            'funding_sources': len(self.funding_sources),
            'milestones_total': len(self.milestones),
            'milestones_completed': sum(1 for m in self.milestones if m['completed'])
        }
    
    def export_json(self, filepath: str):
        """Export project report to JSON"""
        with open(filepath, 'w') as f:
            json.dump(self.generate_report(), f, indent=2)


class CooperativeEconomy:
    """
    Model cooperative economic structures
    
    Implements Rochdale Principles:
    1. Voluntary and open membership
    2. Democratic member control (one member, one vote)
    3. Member economic participation
    4. Autonomy and independence
    5. Education, training, and information
    6. Cooperation among cooperatives
    7. Concern for community
    """
    
    def __init__(self, name: str, sector: str = "general"):
        """
        Initialize cooperative
        
        Args:
            name: Cooperative name
            sector: Economic sector
        """
        self.name = name
        self.sector = sector
        self.members: List[Dict] = []
        self.capital_pool = 0.0
        self.surplus_fund = 0.0
        self.transactions: List[Dict] = []
        self.founded = datetime.now()
        self.by_laws: Dict = {}
    
    def add_member(self, member_id: str, contribution: float,
                   skills: List[str], voting_power: int = 1):
        """
        Add member to cooperative
        
        Args:
            member_id: Unique member identifier
            contribution: Initial capital contribution
            skills: Member skills
            voting_power: Voting power (usually 1 for democratic control)
        """
        member = {
            'id': member_id,
            'contribution': contribution,
            'skills': skills,
            'joined': datetime.now(),
            'voting_power': voting_power,
            'earnings': 0.0,
            'patronage': 0.0  # Track member's use of cooperative
        }
        self.members.append(member)
        self.capital_pool += contribution
    
    def record_patronage(self, member_id: str, amount: float):
        """Record member's patronage (usage of cooperative services)"""
        for member in self.members:
            if member['id'] == member_id:
                member['patronage'] += amount
                return True
        return False
    
    def add_surplus(self, amount: float):
        """Add surplus to cooperative fund"""
        self.surplus_fund += amount
    
    def distribute_surplus(self, method: str = 'patronage') -> Dict:
        """
        Distribute surplus according to cooperative principles
        
        Methods:
        - 'equal': Equal distribution among members
        - 'patronage': Based on member's use of cooperative
        - 'contribution': Based on capital contribution
        - 'hybrid': Combination of patronage and contribution
        
        Args:
            method: Distribution method
        
        Returns:
            Distribution summary
        """
        if not self.members or self.surplus_fund <= 0:
            return {'error': 'No surplus or members to distribute'}
        
        distribution = {}
        
        if method == 'equal':
            per_member = self.surplus_fund / len(self.members)
            for member in self.members:
                member['earnings'] += per_member
                distribution[member['id']] = per_member
        
        elif method == 'patronage':
            total_patronage = sum(m['patronage'] for m in self.members)
            if total_patronage > 0:
                for member in self.members:
                    share = (member['patronage'] / total_patronage) * self.surplus_fund
                    member['earnings'] += share
                    distribution[member['id']] = share
        
        elif method == 'contribution':
            total_contribution = sum(m['contribution'] for m in self.members)
            if total_contribution > 0:
                for member in self.members:
                    share = (member['contribution'] / total_contribution) * self.surplus_fund
                    member['earnings'] += share
                    distribution[member['id']] = share
        
        elif method == 'hybrid':
            # 50% patronage, 50% contribution
            patronage_dist = self._calculate_distribution('patronage', self.surplus_fund * 0.5)
            contribution_dist = self._calculate_distribution('contribution', self.surplus_fund * 0.5)
            
            for member in self.members:
                total = patronage_dist.get(member['id'], 0) + contribution_dist.get(member['id'], 0)
                member['earnings'] += total
                distribution[member['id']] = total
        
        # Record transaction
        self.transactions.append({
            'type': 'surplus_distribution',
            'amount': self.surplus_fund,
            'method': method,
            'distribution': distribution,
            'date': datetime.now()
        })
        
        distributed = self.surplus_fund
        self.surplus_fund = 0
        
        return {
            'method': method,
            'total_distributed': distributed,
            'distribution': distribution
        }
    
    def _calculate_distribution(self, method: str, amount: float) -> Dict:
        """Calculate distribution without applying it"""
        distribution = {}
        
        if method == 'patronage':
            total = sum(m['patronage'] for m in self.members)
            if total > 0:
                for member in self.members:
                    distribution[member['id']] = (member['patronage'] / total) * amount
        
        elif method == 'contribution':
            total = sum(m['contribution'] for m in self.members)
            if total > 0:
                for member in self.members:
                    distribution[member['id']] = (member['contribution'] / total) * amount
        
        return distribution
    
    def democratic_vote(self, proposal: str, votes: Dict[str, bool]) -> Dict:
        """
        Process democratic vote
        
        Args:
            proposal: Proposal description
            votes: Dictionary mapping member_id to vote (True=yes, False=no)
        
        Returns:
            Vote results
        """
        yes_votes = 0
        no_votes = 0
        yes_weight = 0
        no_weight = 0
        
        for member_id, vote in votes.items():
            member = next((m for m in self.members if m['id'] == member_id), None)
            if member:
                if vote:
                    yes_votes += 1
                    yes_weight += member['voting_power']
                else:
                    no_votes += 1
                    no_weight += member['voting_power']
        
        total_members = len(self.members)
        total_voting_power = sum(m['voting_power'] for m in self.members)
        
        result = {
            'proposal': proposal,
            'yes_votes': yes_votes,
            'no_votes': no_votes,
            'yes_weight': yes_weight,
            'no_weight': no_weight,
            'turnout': (len(votes) / total_members * 100) if total_members > 0 else 0,
            'passed': yes_weight > no_weight,
            'timestamp': datetime.now().isoformat()
        }
        
        return result
    
    def get_member_summary(self, member_id: str) -> Optional[Dict]:
        """Get summary for specific member"""
        member = next((m for m in self.members if m['id'] == member_id), None)
        if not member:
            return None
        
        return {
            'id': member['id'],
            'contribution': member['contribution'],
            'earnings': member['earnings'],
            'patronage': member['patronage'],
            'joined': member['joined'].isoformat(),
            'voting_power': member['voting_power']
        }
    
    def generate_report(self) -> Dict:
        """Generate cooperative status report"""
        return {
            'name': self.name,
            'sector': self.sector,
            'founded': self.founded.isoformat(),
            'member_count': len(self.members),
            'capital_pool': self.capital_pool,
            'surplus_fund': self.surplus_fund,
            'total_distributed': sum(t['amount'] for t in self.transactions 
                                     if t['type'] == 'surplus_distribution'),
            'transaction_count': len(self.transactions)
        }


class TimeBanking:
    """
    Time banking system for skill exchange
    
    In time banking, everyone's time is valued equally.
    One hour of service equals one time credit, regardless
    of the service provided.
    """
    
    def __init__(self, name: str = "Community Time Bank"):
        """
        Initialize time bank
        
        Args:
            name: Time bank name
        """
        self.name = name
        self.members: Dict[str, Dict] = {}
        self.offers: List[Dict] = []
        self.transactions: List[Dict] = []
        self.created = datetime.now()
    
    def register_member(self, member_id: str, name: str,
                       skills: List[str], location: str = "",
                       initial_credits: float = 0):
        """
        Register new time bank member
        
        Args:
            member_id: Unique identifier
            name: Member name
            skills: Skills member can offer
            location: Geographic location
            initial_credits: Starting time credits
        """
        self.members[member_id] = {
            'name': name,
            'skills': skills,
            'location': location,
            'time_credits': initial_credits,
            'hours_given': 0.0,
            'hours_received': 0.0,
            'joined': datetime.now(),
            'reputation': 5.0  # Starting reputation (1-5 scale)
        }
    
    def offer_service(self, member_id: str, service: str,
                     description: str, hours: float,
                     category: str = "general") -> Optional[int]:
        """
        Member offers service to time bank
        
        Args:
            member_id: Offering member
            service: Service name
            description: Service description
            hours: Hours available
            category: Service category
        
        Returns:
            Offer ID or None if member not found
        """
        if member_id not in self.members:
            return None
        
        offer = {
            'id': len(self.offers),
            'member_id': member_id,
            'member_name': self.members[member_id]['name'],
            'service': service,
            'description': description,
            'hours': hours,
            'category': category,
            'status': 'available',
            'created': datetime.now()
        }
        
        self.offers.append(offer)
        return offer['id']
    
    def find_offers(self, category: Optional[str] = None,
                   skill: Optional[str] = None) -> List[Dict]:
        """Find available service offers"""
        available = [o for o in self.offers if o['status'] == 'available']
        
        if category:
            available = [o for o in available if o['category'] == category]
        
        if skill:
            available = [o for o in available 
                        if skill.lower() in o['service'].lower()]
        
        return available
    
    def exchange_service(self, offer_id: int, receiver_id: str,
                        actual_hours: Optional[float] = None) -> bool:
        """
        Complete service exchange
        
        Args:
            offer_id: ID of service offer
            receiver_id: Member receiving service
            actual_hours: Actual hours exchanged (defaults to offer hours)
        
        Returns:
            True if successful
        """
        if offer_id >= len(self.offers) or receiver_id not in self.members:
            return False
        
        offer = self.offers[offer_id]
        
        if offer['status'] != 'available':
            return False
        
        provider_id = offer['member_id']
        hours = actual_hours if actual_hours is not None else offer['hours']
        
        # Transfer time credits
        self.members[provider_id]['time_credits'] += hours
        self.members[provider_id]['hours_given'] += hours
        self.members[receiver_id]['time_credits'] -= hours
        self.members[receiver_id]['hours_received'] += hours
        
        # Record transaction
        self.transactions.append({
            'offer_id': offer_id,
            'provider_id': provider_id,
            'provider_name': self.members[provider_id]['name'],
            'receiver_id': receiver_id,
            'receiver_name': self.members[receiver_id]['name'],
            'hours': hours,
            'service': offer['service'],
            'date': datetime.now()
        })
        
        offer['status'] = 'completed'
        return True
    
    def get_member_balance(self, member_id: str) -> Optional[Dict]:
        """Get member's time banking balance"""
        if member_id not in self.members:
            return None
        
        m = self.members[member_id]
        return {
            'member_id': member_id,
            'name': m['name'],
            'time_credits': m['time_credits'],
            'hours_given': m['hours_given'],
            'hours_received': m['hours_received'],
            'net_contribution': m['hours_given'] - m['hours_received'],
            'reputation': m['reputation']
        }
    
    def get_bank_statistics(self) -> Dict:
        """Get overall time bank statistics"""
        total_hours_exchanged = sum(t['hours'] for t in self.transactions)
        
        return {
            'name': self.name,
            'member_count': len(self.members),
            'total_offers': len(self.offers),
            'active_offers': sum(1 for o in self.offers if o['status'] == 'available'),
            'total_transactions': len(self.transactions),
            'total_hours_exchanged': total_hours_exchanged,
            'average_hours_per_transaction': (total_hours_exchanged / len(self.transactions) 
                                             if self.transactions else 0)
        }


class UBISimulator:
    """
    Universal Basic Income Simulator
    
    Models various UBI implementations and their economic impacts.
    """
    
    def __init__(self, population: int, gdp: float, ubi_amount: float,
                 currency: str = 'USD'):
        """
        Initialize UBI simulation
        
        Args:
            population: Total population
            gdp: Gross Domestic Product
            ubi_amount: Monthly UBI per person
            currency: Currency code
        """
        self.population = population
        self.gdp = gdp
        self.ubi_amount = ubi_amount
        self.currency = currency
        self.total_ubi_cost = population * ubi_amount * 12  # Annual
    
    def calculate_funding_options(self) -> Dict:
        """
        Calculate different funding mechanisms
        
        Returns:
            Dictionary of funding options with required rates
        """
        gdp_percentage = (self.total_ubi_cost / self.gdp) * 100
        
        return {
            'total_annual_cost': self.total_ubi_cost,
            'percent_of_gdp': gdp_percentage,
            'per_capita_cost': self.ubi_amount * 12,
            'funding_mechanisms': {
                'wealth_tax': {
                    'description': 'Annual wealth tax on top 1%',
                    'rate_required': self.total_ubi_cost / (self.gdp * 0.35),
                    'rate_percent': (self.total_ubi_cost / (self.gdp * 0.35)) * 100
                },
                'vat_increase': {
                    'description': 'VAT increase',
                    'rate_required': self.total_ubi_cost / (self.gdp * 0.15),
                    'rate_percent': (self.total_ubi_cost / (self.gdp * 0.15)) * 100
                },
                'carbon_tax': {
                    'description': 'Carbon tax revenue',
                    'required_revenue': self.total_ubi_cost,
                    'per_ton_rate': self.total_ubi_cost / 5e9  # Assuming 5Gt CO2
                },
                'defense_reallocation': {
                    'description': 'Defense budget reallocation',
                    'us_defense_budget': 886e9,  # 2024 US defense budget
                    'percent_of_us_defense': (self.total_ubi_cost / 886e9) * 100
                },
                'automation_dividend': {
                    'description': 'Tax on automation/AI productivity gains',
                    'assumed_productivity_gain': self.gdp * 0.02,  # 2% GDP gain
                    'tax_rate_required': (self.total_ubi_cost / (self.gdp * 0.02)) * 100
                }
            }
        }
    
    def poverty_impact(self, poverty_line: float,
                      current_poverty_rate: float) -> Dict:
        """
        Estimate poverty reduction impact
        
        Args:
            poverty_line: Annual poverty threshold
            current_poverty_rate: Current poverty rate (0-100)
        
        Returns:
            Poverty impact analysis
        """
        annual_ubi = self.ubi_amount * 12
        
        # Simplified model
        income_gap = max(0, poverty_line - annual_ubi)
        
        # Estimate how many people UBI would lift above poverty line
        estimated_reduction = min(90, (annual_ubi / poverty_line) * 100)
        
        return {
            'annual_ubi': annual_ubi,
            'poverty_line': poverty_line,
            'income_gap_after_ubi': income_gap,
            'estimated_poverty_reduction_percent': estimated_reduction,
            'current_poverty_rate': current_poverty_rate,
            'projected_poverty_rate': max(0, current_poverty_rate - estimated_reduction),
            'people_lifted_out_of_poverty': int(
                self.population * (estimated_reduction / 100)
            )
        }
    
    def economic_multiplier(self, marginal_propensity_to_consume: float = 0.9) -> Dict:
        """
        Calculate economic multiplier effect
        
        Args:
            marginal_propensity_to_consume: Fraction of UBI spent (default 0.9)
        
        Returns:
            Multiplier analysis
        """
        # Simple Keynesian multiplier
        multiplier = 1 / (1 - marginal_propensity_to_consume)
        
        total_injection = self.total_ubi_cost
        total_economic_impact = total_injection * multiplier
        
        return {
            'marginal_propensity_to_consume': marginal_propensity_to_consume,
            'multiplier': multiplier,
            'total_ubi_injection': total_injection,
            'total_economic_impact': total_economic_impact,
            'additional_gdp_percent': (total_economic_impact / self.gdp) * 100
        }
    
    def generate_full_report(self, poverty_line: float,
                            current_poverty_rate: float) -> Dict:
        """Generate comprehensive UBI analysis report"""
        return {
            'parameters': {
                'population': self.population,
                'gdp': self.gdp,
                'monthly_ubi': self.ubi_amount,
                'currency': self.currency
            },
            'cost_analysis': self.calculate_funding_options(),
            'poverty_impact': self.poverty_impact(poverty_line, current_poverty_rate),
            'economic_multiplier': self.economic_multiplier()
        }


def main():
    """Demonstration of regenerative finance toolkit"""
    print("=" * 60)
    print("REGENERATIVE FINANCE (ReFi) TOOLKIT")
    print("=" * 60)
    
    # 1. Regenerative Project
    print("\n1. Regenerative Project Example")
    print("-" * 40)
    
    project = RegenerativeProject(
        name="Community Garden Network",
        project_type="Urban Agriculture",
        location="Portland, Oregon",
        description="Network of community gardens providing fresh produce"
    )
    
    project.add_metric(ImpactMetric(
        category="carbon",
        baseline=100,
        current=75,
        target=50,
        unit="tons CO2e/year"
    ))
    
    project.add_metric(ImpactMetric(
        category="social",
        baseline=50,
        current=120,
        target=200,
        unit="people fed"
    ))
    
    project.add_stakeholder("Alice Johnson", "Coordinator", 5000)
    project.add_funding("City Grant", 25000)
    
    report = project.generate_report()
    print(f"  Project: {report['project_name']}")
    print(f"  Impact Score: {report['impact_score']:.2f}%")
    print(f"  Total Funding: ${report['total_funding']:,.2f}")
    
    # 2. Cooperative Economy
    print("\n2. Cooperative Economy Example")
    print("-" * 40)
    
    coop = CooperativeEconomy("Riverside Food Co-op", "food")
    coop.add_member("member_001", 1000, ["farming", "logistics"])
    coop.add_member("member_002", 500, ["marketing", "sales"])
    coop.add_member("member_003", 750, ["accounting", "admin"])
    
    coop.add_surplus(5000)
    distribution = coop.distribute_surplus('equal')
    
    print(f"  Cooperative: {coop.name}")
    print(f"  Members: {len(coop.members)}")
    print(f"  Surplus Distributed: ${distribution['total_distributed']:,.2f}")
    print(f"  Per Member: ${distribution['total_distributed']/len(coop.members):,.2f}")
    
    # 3. Time Banking
    print("\n3. Time Banking Example")
    print("-" * 40)
    
    tb = TimeBanking("Neighborhood Exchange")
    tb.register_member("m1", "John", ["plumbing", "carpentry"], "North Side")
    tb.register_member("m2", "Sarah", ["tutoring", "gardening"], "South Side")
    
    offer_id = tb.offer_service("m1", "Plumbing Repair", "Fix leaky faucets", 2)
    tb.exchange_service(offer_id, "m2")
    
    balance = tb.get_member_balance("m1")
    print(f"  Time Bank: {tb.name}")
    print(f"  John's Credits: {balance['time_credits']}")
    print(f"  Hours Given: {balance['hours_given']}")
    
    # 4. UBI Simulation
    print("\n4. UBI Simulation Example")
    print("-" * 40)
    
    ubi = UBISimulator(
        population=331_000_000,  # US population
        gdp=27_360_000_000_000,  # US GDP
        ubi_amount=1000  # $1000/month
    )
    
    funding = ubi.calculate_funding_options()
    print(f"  Annual UBI Cost: ${funding['total_annual_cost']:,.0f}")
    print(f"  % of GDP: {funding['percent_of_gdp']:.1f}%")
    print(f"  Required Wealth Tax: {funding['funding_mechanisms']['wealth_tax']['rate_percent']:.1f}%")
    
    poverty = ubi.poverty_impact(poverty_line=15000, current_poverty_rate=11.5)
    print(f"  People Lifted from Poverty: {poverty['people_lifted_out_of_poverty']:,.0f}")
    
    print("\n" + "=" * 60)
    print("All economic models are functional and ready for use.")
    print("=" * 60)


if __name__ == "__main__":
    main()
