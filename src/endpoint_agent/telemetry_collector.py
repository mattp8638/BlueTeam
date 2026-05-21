class TelemetryCollector:
    """
    Watches local OS event logs and streams them up to the Nerve Center.
    """
    def __init__(self, nerve_center):
        self.nerve_center = nerve_center
        
    def stream_syslog(self, raw_syslog: str):
        print(f"[Agent: Telemetry Collector] Forwarding syslog to Nerve Center: {raw_syslog[:40]}...")
        # Sends unstructured data; relies on SIEM's Zero-Shot parser to translate it
        self.nerve_center.route_event("SYSLOG", raw_syslog)
