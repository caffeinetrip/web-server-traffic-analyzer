import sys
import argparse
from datetime import datetime
from collections import Counter, defaultdict
from dataclasses import dataclass

@dataclass
class LogRecord:
    timestamp: int
    ip_address: str
    http_method: str
    url: str
    status_code: int
    response_size: int
    
    def __post_init__(self):
        if self.timestamp < 0:
            raise ValueError(f"Invalid timestamp: {self.timestamp}")
        
        parts = self.ip_address.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP format: {self.ip_address}")
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                raise ValueError(f"Invalid IP: {self.ip_address}")
        
        valid_methods = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
        if self.http_method not in valid_methods:
            raise ValueError(f"Invalid method: {self.http_method}")
        
        if not self.url.startswith('/'):
            raise ValueError(f"Invalid URL: {self.url}")
        
        if not 100 <= self.status_code <= 599:
            raise ValueError(f"Invalid status: {self.status_code}")

        if self.response_size < 0:
            raise ValueError(f"Invalid size: {self.response_size}")

class LogParser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.records = []
        self.parse_errors = []

    def parse_log_line(self, line, line_number):
        line = line.strip()
        
        if not line:
            return None
        
        fields = line.split()
        if len(fields) != 6:
            self.parse_errors.append((line_number, line, f"Expected 6 fields, got {len(fields)}"))
            return None

        record = LogRecord(
            timestamp=int(fields[0]),
            ip_address=fields[1],
            http_method=fields[2].upper(),
            url=fields[3],
            status_code=int(fields[4]),
            response_size=int(fields[5])
        )
        
        return record


    def read_and_parse(self):
        with open(self.filepath, 'r') as f:
            line_number = 0
            
            for line in f:
                line_number += 1
                record = self.parse_log_line(line, line_number)
                
                if record:
                    self.records.append(record)
        
        return self.records
        


    def get_statistics(self):
        
        return {
            'total_lines': len(self.records) + len(self.parse_errors),
            'parsed': len(self.records),
            'errors': len(self.parse_errors)
        }

class LogFilter:
    def __init__(self, method=None, status=None, start_time=None, end_time=None):
        pass

    def apply(self, records):
        pass

class TrafficAnalyzer:
    def __init__(self, records):
        self.records = records
        self.stats = {}

    def calculate_basic_stats(self):
        return {
            'total_requests': len(self.records),
            'unique_ips': len(set(i.ip_address for i in self.records)),
            'total_data': sum(i.response_size for i in self.records)
        }

    def get_top_ips(self, n=3):
        counter = Counter(i.ip_address for i in self.records)
        return counter.most_common(n)

    def get_method_distribution(self):
        counter = Counter(i.http_method for i in self.records)
        total = len(self.records)
        
        return {method: (count/total)*100 for method, count in counter.items()}

    def get_top_urls(self, n=5):
            counter = Counter(i.url for i in self.records)
            return counter.most_common(n)

    def calculate_error_metrics(self):
        success = [i for i in self.records if 200 <= i.status_code < 300]
        errors_4xx = [i for i in self.records if 400 <= i.status_code < 500]
        errors_5xx = [i for i in self.records if 500 <= i.status_code < 600]
        
        avg_size = sum(r.response_size for r in success) / len(success) if success else 0
        
        return {
            'success_2xx': len(success),
            'errors_4xx': len(errors_4xx),
            'errors_5xx': len(errors_5xx),
            'avg_response_2xx': avg_size
        }

    def analyze_last_24h(self):
        if not self.records:
            return {'unique_ips': 0, 'requests_per_hour': {}}
        
        max_ts = max(i.timestamp for i in self.records)
        cutoff = max_ts - (24 * 60 * 60)
        
        last_24h = [i for i in self.records if i.timestamp >= cutoff]
        unique_ips = len(set(i.ip_address for i in last_24h))
        
        per_hour = defaultdict(int)
        for i in last_24h:
            hour = datetime.fromtimestamp(i.timestamp).hour
            per_hour[hour] += 1
        
        return {
            'unique_ips': unique_ips,
            'requests_per_hour': dict(per_hour)
        }

    def generate_report(self, filter_settings, top_n=3):
        lines = ["====== TRAFFIC ANALYSIS REPORT ======\n"]
        
        lines.append("Filter settings:")
        
        lines.append(f"- Time range: {filter_settings.get('time_range', 'all time')}")
        lines.append(f"- Method filter: {filter_settings.get('method', 'all methods')}")
        lines.append(f"- Status filter: {filter_settings.get('status', 'all statuses')}\n")


        basic = self.calculate_basic_stats()
        
        lines.append("Basic statistics:")
        lines.append(f"Total requests: {basic['total_requests']}")
        lines.append(f"Unique IPs: {basic['unique_ips']}")
        lines.append(f"Total data transferred: {basic['total_data']} ({format_bytes(basic['total_data'])})\n")
        
        methods = self.get_method_distribution()
        lines.append("Request distribution:")
        
        for method in sorted(methods.keys()):
            lines.append(f"- {method}: {methods[method]:.1f}%")
            
        lines.append("")
        
        errors = self.calculate_error_metrics()
        lines.append("Performance metrics:")
        lines.append(f"- Successful requests (2xx): {errors['success_2xx']}")
        lines.append(f"- Client errors (4xx): {errors['errors_4xx']}")
        lines.append(f"- Server errors (5xx): {errors['errors_5xx']}")
        lines.append(f"- Average response size (2xx): {errors['avg_response_2xx']:.0f} bytes\n")
        
        top_ips = self.get_top_ips(top_n)
        lines.append(f"Top {top_n} active IPs:")
        
        for i, (ip, count) in enumerate(top_ips, 1):
            lines.append(f"{i}. {ip}: {count} requests")
            
        lines.append("")
        
        top_urls = self.get_top_urls(5)
        lines.append("Top 5 requested URLs:")
        
        for i, (url, count) in enumerate(top_urls, 1):
            lines.append(f"{i}. {url}: {count}")
            
        lines.append("")
        
        last_24h = self.analyze_last_24h()
        lines.append("Recent activity (last 24h):")
        lines.append(f"- Unique IPs: {last_24h['unique_ips']}")
        
        if last_24h['requests_per_hour']:
            hourly = ', '.join(f"{h}h: {c}" for h, c in sorted(last_24h['requests_per_hour'].items()))
            lines.append(f"- Requests per hour: [{hourly}]")
        
        return '\n'.join(lines)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='web server traffic analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,)
    
    parser.add_argument('logfile', help='Path to log file')
    parser.add_argument('--method', choices=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
    parser.add_argument('--status', help='Status code or range (e.g. 200 or 400-499)')
    parser.add_argument('--start', type=int, help='Start timestamp')
    parser.add_argument('--end', type=int, help='End timestamp')
    parser.add_argument('--top', type=int, default=3, help='Top N IPs (default: 3)')
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    parser = LogParser(args.logfile)
    records = parser.read_and_parse()
    
    if not records:
        return 0
    
    # log_filter = LogFilter(
    #         method=args.method,
    #         status=args.status,
    #         start_time=args.start,
    #         end_time=args.end
    #     )


if __name__ == '__main__':
    sys.exit(main())
