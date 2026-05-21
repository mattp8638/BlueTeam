import time
import uuid

class PipelineMonitor:
    """
    Data Quality SLA Monitoring.
    Continuous background tracking of pipeline latency and error rates.
    Must maintain 99.9% success and <250ms latency.
    """
    
    def __init__(self):
        self.total_processed = 0
        self.total_errors = 0
        self.latency_samples = []

    def start_timer(self) -> float:
        return time.perf_counter()

    def record_metrics(self, start_time: float, success: bool):
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        self.total_processed += 1
        if not success:
            self.total_errors += 1
            
        self.latency_samples.append(latency_ms)
        
        # Enforce Latency SLA
        if latency_ms > 250.0:
            print(f"[SLA ALARM] Latency spike detected! Processing took {latency_ms:.2f}ms (Threshold: 250ms)")
            
        # Enforce Quality SLA
        if self.total_processed > 100:
            error_rate = (self.total_errors / self.total_processed) * 100
            success_rate = 100.0 - error_rate
            if success_rate < 99.9:
                 print(f"[SLA ALARM] Data Quality Drop! Success rate is {success_rate:.2f}% (Threshold: 99.9%)")

    def print_report(self):
        avg_latency = sum(self.latency_samples) / max(len(self.latency_samples), 1)
        success_rate = 100.0 - ((self.total_errors / max(self.total_processed, 1)) * 100)
        print("\n--- Pipeline SLA Health Report ---")
        print(f"Events Processed: {self.total_processed}")
        print(f"Average Latency: {avg_latency:.2f}ms")
        print(f"Success Rate: {success_rate:.2f}%")
