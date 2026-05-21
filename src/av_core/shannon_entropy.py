import math

class ShannonEntropyCalculator:
    """
    Mathematical Heuristics Engine.
    Calculates the Shannon Entropy of a file to detect packed, obfuscated, or encrypted payloads.
    Typical executables have an entropy of ~4.0 to 6.0.
    Encrypted payloads (like ransomware) approach 8.0.
    """
    
    @classmethod
    def calculate_entropy(cls, raw_bytes: bytes) -> float:
        if not raw_bytes:
            return 0.0
            
        entropy = 0
        file_length = len(raw_bytes)
        
        # Calculate frequency of each byte (0-255)
        frequencies = [0] * 256
        for byte in raw_bytes:
            frequencies[byte] += 1
            
        # Shannon Entropy Formula: H(X) = -sum(P(x) * log2(P(x)))
        for count in frequencies:
            if count > 0:
                probability = count / file_length
                entropy -= probability * math.log2(probability)
                
        return entropy

    @classmethod
    def analyze(cls, file_name: str, raw_bytes: bytes) -> dict:
        print(f"[Entropy Engine] Analyzing {file_name}...")
        
        score = cls.calculate_entropy(raw_bytes)
        print(f" -> Shannon Entropy Score: {score:.2f}")
        
        is_malicious = False
        if score > 7.5:
            print(" -> [ALERT] Highly compressed/encrypted payload detected!")
            is_malicious = True
            
        return {
            "engine": "Heuristics",
            "score": score,
            "is_malicious": is_malicious,
            "details": f"Entropy: {score:.2f}"
        }
