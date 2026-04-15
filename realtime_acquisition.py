#!/usr/bin/env python3
"""
Real-time Data Acquisition System (RDAS)
Continuous monitoring and data ingestion platform

Features:
- Multi-source stream processing
- Event-driven architecture
- Automated alerting
- Data pipeline orchestration
- Time-series data handling

License: MIT
Version: 2.0 (April 2026)
"""

import asyncio
import aiohttp
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable, Any, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
import re


class StreamType(Enum):
    """Types of data streams"""
    RSS_FEED = auto()
    API_POLLING = auto()
    WEBSOCKET = auto()
    WEBHOOK = auto()
    LOG_FILE = auto()
    DATABASE = auto()
    SOCIAL_MEDIA = auto()
    NEWS_API = auto()
    CUSTOM = auto()


class EventPriority(Enum):
    """Event priority levels"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class DataEvent:
    """Data event structure"""
    event_id: str
    source: str
    event_type: str
    timestamp: datetime
    data: Dict
    priority: EventPriority = EventPriority.MEDIUM
    tags: Set[str] = field(default_factory=set)
    processed: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'event_id': self.event_id,
            'source': self.source,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'priority': self.priority.name,
            'tags': list(self.tags),
            'processed': self.processed
        }


@dataclass
class StreamConfig:
    """Stream configuration"""
    name: str
    stream_type: StreamType
    source_url: str
    poll_interval: float = 60.0
    timeout: float = 30.0
    retries: int = 3
    enabled: bool = True
    filters: List[str] = field(default_factory=list)
    transformers: List[str] = field(default_factory=list)


class RealtimeAcquisitionSystem:
    """
    Real-time Data Acquisition System
    
    Core capabilities:
    - Continuous data stream monitoring
    - Event-driven processing
    - Configurable data pipelines
    - Alert and notification system
    """
    
    def __init__(self):
        self.streams: Dict[str, StreamConfig] = {}
        self.active_tasks: Dict[str, asyncio.Task] = {}
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.processed_events: deque = deque(maxlen=10000)
        self.alert_handlers: List[Callable] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = False
        self.metrics: Dict = {
            'events_processed': 0,
            'events_per_second': 0.0,
            'active_streams': 0,
            'errors': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        timeout = aiohttp.ClientTimeout(total=60)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'RDAS/2.0 (Real-time Data Acquisition)'
            }
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop_all_streams()
        if self.session:
            await self.session.close()
    
    def register_stream(self, config: StreamConfig):
        """Register a new data stream"""
        self.streams[config.name] = config
        print(f"Registered stream: {config.name} ({config.stream_type.name})")
    
    def register_event_handler(self, event_type: str, 
                               handler: Callable[[DataEvent], Any]):
        """Register event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def register_alert_handler(self, handler: Callable[[DataEvent], Any]):
        """Register alert handler"""
        self.alert_handlers.append(handler)
    
    async def start_stream(self, stream_name: str):
        """Start a specific stream"""
        if stream_name not in self.streams:
            raise ValueError(f"Stream not found: {stream_name}")
        
        config = self.streams[stream_name]
        
        if not config.enabled:
            print(f"Stream {stream_name} is disabled")
            return
        
        # Create appropriate stream processor
        if config.stream_type == StreamType.RSS_FEED:
            task = asyncio.create_task(self._process_rss_stream(config))
        elif config.stream_type == StreamType.API_POLLING:
            task = asyncio.create_task(self._process_api_stream(config))
        elif config.stream_type == StreamType.NEWS_API:
            task = asyncio.create_task(self._process_news_stream(config))
        else:
            task = asyncio.create_task(self._process_generic_stream(config))
        
        self.active_tasks[stream_name] = task
        self.metrics['active_streams'] = len(self.active_tasks)
        
        print(f"Started stream: {stream_name}")
    
    async def stop_stream(self, stream_name: str):
        """Stop a specific stream"""
        if stream_name in self.active_tasks:
            self.active_tasks[stream_name].cancel()
            try:
                await self.active_tasks[stream_name]
            except asyncio.CancelledError:
                pass
            del self.active_tasks[stream_name]
            self.metrics['active_streams'] = len(self.active_tasks)
            print(f"Stopped stream: {stream_name}")
    
    async def stop_all_streams(self):
        """Stop all active streams"""
        for stream_name in list(self.active_tasks.keys()):
            await self.stop_stream(stream_name)
    
    async def start_all_streams(self):
        """Start all enabled streams"""
        for stream_name in self.streams:
            await self.start_stream(stream_name)
    
    # Stream processors
    
    async def _process_rss_stream(self, config: StreamConfig):
        """Process RSS feed stream"""
        import xml.etree.ElementTree as ET
        
        while True:
            try:
                async with self.session.get(
                    config.source_url,
                    timeout=config.timeout
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        try:
                            root = ET.fromstring(content)
                            
                            # Parse RSS items
                            ns = {'atom': 'http://www.w3.org/2005/Atom'}
                            
                            # Try RSS 2.0 format
                            items = root.findall('.//item')
                            
                            # Try Atom format
                            if not items:
                                items = root.findall('atom:entry', ns)
                            
                            for item in items:
                                title = item.findtext('title', '') or \
                                       item.findtext('atom:title', '', ns)
                                link = item.findtext('link', '') or \
                                      item.findtext('atom:link', '', ns)
                                pub_date = item.findtext('pubDate', '') or \
                                          item.findtext('atom:published', '', ns)
                                description = item.findtext('description', '') or \
                                             item.findtext('atom:summary', '', ns)
                                
                                # Apply filters
                                if config.filters:
                                    content = f"{title} {description}"
                                    if not any(f.lower() in content.lower() 
                                              for f in config.filters):
                                        continue
                                
                                event = DataEvent(
                                    event_id=hashlib.md5(
                                        f"{title}{pub_date}".encode()
                                    ).hexdigest(),
                                    source=config.name,
                                    event_type='rss_item',
                                    timestamp=datetime.now(),
                                    data={
                                        'title': title,
                                        'link': link,
                                        'published': pub_date,
                                        'description': description
                                    },
                                    tags={'rss', config.name}
                                )
                                
                                await self._process_event(event)
                        
                        except ET.ParseError as e:
                            print(f"RSS parse error: {e}")
                
                await asyncio.sleep(config.poll_interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"RSS stream error ({config.name}): {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(config.poll_interval)
    
    async def _process_api_stream(self, config: StreamConfig):
        """Process API polling stream"""
        while True:
            try:
                async with self.session.get(
                    config.source_url,
                    timeout=config.timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        event = DataEvent(
                            event_id=hashlib.md5(
                                json.dumps(data, sort_keys=True).encode()
                            ).hexdigest(),
                            source=config.name,
                            event_type='api_response',
                            timestamp=datetime.now(),
                            data=data,
                            tags={'api', config.name}
                        )
                        
                        await self._process_event(event)
                
                await asyncio.sleep(config.poll_interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"API stream error ({config.name}): {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(config.poll_interval)
    
    async def _process_news_stream(self, config: StreamConfig):
        """Process news API stream"""
        # NewsAPI integration
        api_key = config.source_url.split('apiKey=')[-1] if 'apiKey=' in config.source_url else None
        
        while True:
            try:
                async with self.session.get(
                    config.source_url,
                    timeout=config.timeout
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        articles = data.get('articles', [])
                        
                        for article in articles:
                            event = DataEvent(
                                event_id=hashlib.md5(
                                    article.get('url', '').encode()
                                ).hexdigest(),
                                source=config.name,
                                event_type='news_article',
                                timestamp=datetime.now(),
                                data={
                                    'title': article.get('title'),
                                    'description': article.get('description'),
                                    'url': article.get('url'),
                                    'published_at': article.get('publishedAt'),
                                    'source': article.get('source', {}).get('name'),
                                    'author': article.get('author')
                                },
                                tags={'news', config.name}
                            )
                            
                            await self._process_event(event)
                
                await asyncio.sleep(config.poll_interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"News stream error ({config.name}): {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(config.poll_interval)
    
    async def _process_generic_stream(self, config: StreamConfig):
        """Process generic stream"""
        while True:
            try:
                async with self.session.get(
                    config.source_url,
                    timeout=config.timeout
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        event = DataEvent(
                            event_id=hashlib.md5(content.encode()).hexdigest(),
                            source=config.name,
                            event_type='generic_data',
                            timestamp=datetime.now(),
                            data={'content': content[:10000]},  # Limit size
                            tags={'generic', config.name}
                        )
                        
                        await self._process_event(event)
                
                await asyncio.sleep(config.poll_interval)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Generic stream error ({config.name}): {e}")
                self.metrics['errors'] += 1
                await asyncio.sleep(config.poll_interval)
    
    async def _process_event(self, event: DataEvent):
        """Process a data event"""
        # Add to queue
        await self.event_queue.put(event)
        
        # Call event handlers
        if event.event_type in self.event_handlers:
            for handler in self.event_handlers[event.event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    print(f"Handler error: {e}")
        
        # Check for alerts
        await self._check_alerts(event)
        
        # Store processed event
        event.processed = True
        self.processed_events.append(event)
        
        # Update metrics
        self.metrics['events_processed'] += 1
    
    async def _check_alerts(self, event: DataEvent):
        """Check if event triggers alerts"""
        # Priority-based alerts
        if event.priority in [EventPriority.CRITICAL, EventPriority.HIGH]:
            for handler in self.alert_handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    print(f"Alert handler error: {e}")
    
    async def get_events(self, count: int = 10,
                        event_type: Optional[str] = None,
                        source: Optional[str] = None) -> List[DataEvent]:
        """Get recent events with optional filtering"""
        events = list(self.processed_events)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if source:
            events = [e for e in events if e.source == source]
        
        return events[-count:]
    
    def get_metrics(self) -> Dict:
        """Get system metrics"""
        # Calculate events per second
        if self.processed_events:
            recent_events = [
                e for e in self.processed_events
                if (datetime.now() - e.timestamp).seconds < 60
            ]
            self.metrics['events_per_second'] = len(recent_events) / 60.0
        
        return self.metrics.copy()
    
    # Pre-built stream configurations
    
    @staticmethod
    def create_rss_stream(name: str, url: str, 
                          filters: Optional[List[str]] = None,
                          interval: float = 300.0) -> StreamConfig:
        """Create RSS feed stream configuration"""
        return StreamConfig(
            name=name,
            stream_type=StreamType.RSS_FEED,
            source_url=url,
            poll_interval=interval,
            filters=filters or []
        )
    
    @staticmethod
    def create_newsapi_stream(name: str, api_key: str,
                              query: str,
                              interval: float = 300.0) -> StreamConfig:
        """Create NewsAPI stream configuration"""
        url = f"https://newsapi.org/v2/everything?q={query}&apiKey={api_key}"
        
        return StreamConfig(
            name=name,
            stream_type=StreamType.NEWS_API,
            source_url=url,
            poll_interval=interval
        )
    
    @staticmethod
    def create_github_stream(name: str, 
                             query: str,
                             interval: float = 60.0) -> StreamConfig:
        """Create GitHub search stream configuration"""
        url = f"https://api.github.com/search/repositories?q={query}&sort=updated"
        
        return StreamConfig(
            name=name,
            stream_type=StreamType.API_POLLING,
            source_url=url,
            poll_interval=interval
        )


# Data Pipeline Orchestrator
class DataPipeline:
    """Data processing pipeline"""
    
    def __init__(self, name: str):
        self.name = name
        self.stages: List[Callable] = []
        self.output_handlers: List[Callable] = []
    
    def add_stage(self, processor: Callable[[Dict], Dict]):
        """Add processing stage"""
        self.stages.append(processor)
    
    def add_output(self, handler: Callable[[Dict], Any]):
        """Add output handler"""
        self.output_handlers.append(handler)
    
    async def process(self, data: Dict) -> Dict:
        """Process data through pipeline"""
        result = data
        
        # Run through stages
        for stage in self.stages:
            try:
                if asyncio.iscoroutinefunction(stage):
                    result = await stage(result)
                else:
                    result = stage(result)
            except Exception as e:
                print(f"Pipeline stage error: {e}")
                return {'error': str(e), 'original_data': data}
        
        # Send to outputs
        for handler in self.output_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(result)
                else:
                    handler(result)
            except Exception as e:
                print(f"Output handler error: {e}")
        
        return result


# Time-series data handler
class TimeSeriesHandler:
    """Handle time-series data"""
    
    def __init__(self, retention_hours: int = 24):
        self.data: Dict[str, deque] = {}
        self.retention_hours = retention_hours
    
    def add_point(self, metric_name: str, value: float,
                  timestamp: Optional[datetime] = None):
        """Add data point"""
        if metric_name not in self.data:
            self.data[metric_name] = deque()
        
        ts = timestamp or datetime.now()
        
        self.data[metric_name].append({
            'timestamp': ts.isoformat(),
            'value': value
        })
        
        # Clean old data
        self._clean_old_data(metric_name)
    
    def _clean_old_data(self, metric_name: str):
        """Remove data older than retention period"""
        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        
        while (self.data[metric_name] and 
               datetime.fromisoformat(self.data[metric_name][0]['timestamp']) < cutoff):
            self.data[metric_name].popleft()
    
    def get_series(self, metric_name: str,
                   start: Optional[datetime] = None,
                   end: Optional[datetime] = None) -> List[Dict]:
        """Get time series data"""
        if metric_name not in self.data:
            return []
        
        series = list(self.data[metric_name])
        
        if start:
            series = [
                p for p in series 
                if datetime.fromisoformat(p['timestamp']) >= start
            ]
        
        if end:
            series = [
                p for p in series 
                if datetime.fromisoformat(p['timestamp']) <= end
            ]
        
        return series
    
    def get_statistics(self, metric_name: str) -> Dict:
        """Get statistics for metric"""
        if metric_name not in self.data:
            return {}
        
        values = [p['value'] for p in self.data[metric_name]]
        
        if not values:
            return {}
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'avg': sum(values) / len(values),
            'latest': values[-1]
        }


async def demo():
    """Demonstration of real-time acquisition system"""
    print("=" * 70)
    print("REAL-TIME DATA ACQUISITION SYSTEM (RDAS)")
    print("=" * 70)
    
    async with RealtimeAcquisitionSystem() as rdas:
        # Create sample streams
        print("\n1. Creating Sample Streams")
        print("-" * 50)
        
        # GitHub stream
        github_stream = RealtimeAcquisitionSystem.create_github_stream(
            name="github_security",
            query="security vulnerability CVE",
            interval=60.0
        )
        rdas.register_stream(github_stream)
        
        # RSS stream
        rss_stream = RealtimeAcquisitionSystem.create_rss_stream(
            name="security_feed",
            url="https://feeds.feedburner.com/TheHackersNews",
            filters=["vulnerability", "exploit", "CVE"],
            interval=300.0
        )
        rdas.register_stream(rss_stream)
        
        print(f"Registered {len(rdas.streams)} streams")
        
        # Register event handler
        def print_event(event: DataEvent):
            print(f"[{event.source}] {event.event_type}: {event.data.get('title', 'N/A')[:50]}...")
        
        rdas.register_event_handler('rss_item', print_event)
        rdas.register_event_handler('news_article', print_event)
        
        # Start streams
        print("\n2. Starting Streams (5 second demo)")
        print("-" * 50)
        
        # Start GitHub stream
        await rdas.start_stream("github_security")
        
        # Wait and collect events
        await asyncio.sleep(5)
        
        # Get metrics
        print("\n3. System Metrics")
        print("-" * 50)
        
        metrics = rdas.get_metrics()
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
        # Get recent events
        print("\n4. Recent Events")
        print("-" * 50)
        
        events = await rdas.get_events(count=5)
        for event in events:
            print(f"  [{event.source}] {event.event_type}")
        
        # Stop streams
        await rdas.stop_all_streams()
    
    print("\n" + "=" * 70)
    print("Real-time Acquisition System Ready")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo())
