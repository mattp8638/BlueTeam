class FileMonitor:
    """
    Simulates a file system watcher (like utilizing Windows FileSystemWatcher API).
    Intercepts suspicious dropped files and sends them to the AV Engine via the Nerve Center.
    """
    def __init__(self, nerve_center, device_context: dict):
        self.nerve_center = nerve_center
        self.device_context = device_context
        
    def detect_file_drop(self, file_path: str, raw_bytes: bytes):
        print(f"\n[Agent: File Monitor] ALERT: Suspicious file drop detected at {file_path}")
        print("[Agent: File Monitor] Uploading payload to Nerve Center for AV correlation...")
        
        # Route to Nerve Center specifically as a FILE_DROP
        self.nerve_center.route_event(
            source_type="FILE_DROP", 
            raw_data=(file_path, raw_bytes), 
            device_context=self.device_context
        )
