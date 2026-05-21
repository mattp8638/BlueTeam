import math

class SemanticDeduplicationEngine:
    """
    Simulates a Dual-Encoder Text Embedding Network.
    Calculates the high-dimensional vector positions of incoming alert strings.
    If the cosine similarity score >= 0.88 against historical cases, group them.
    """
    
    @staticmethod
    def _mock_text_to_vector(text: str) -> list:
        """
        MOCK FUNCTION: In production, this calls a local sentence-transformer model.
        For now, we generate a simplistic vector based on character frequencies
        just to prove the mathematical pipeline works.
        """
        text = text.lower()
        vec = [0] * 26
        for char in text:
            if 'a' <= char <= 'z':
                vec[ord(char) - 97] += 1
        return vec

    @staticmethod
    def _cosine_similarity(vec1: list, vec2: list) -> float:
        """
        (A · B) / (||A|| * ||B||)
        """
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        magnitude1 = math.sqrt(sum(a * a for a in vec1))
        magnitude2 = math.sqrt(sum(b * b for b in vec2))
        
        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0
            
        return dot_product / (magnitude1 * magnitude2)

    @classmethod
    def evaluate_similarity(cls, new_alert_text: str, historical_case_text: str) -> bool:
        """
        Evaluates if the new alert is semantically identical to a historical case.
        Returns True if score >= 0.88.
        """
        vec_new = cls._mock_text_to_vector(new_alert_text)
        vec_hist = cls._mock_text_to_vector(historical_case_text)
        
        score = cls._cosine_similarity(vec_new, vec_hist)
        print(f"[Semantic Dedup] Cosine Similarity Score: {score:.4f}")
        
        return score >= 0.88

if __name__ == "__main__":
    engine = SemanticDeduplicationEngine()
    
    # Test identical semantics
    print("Testing identical meaning:")
    is_dup = engine.evaluate_similarity(
        "Multiple failed admin logins detected from IP 10.0.0.5",
        "Multiple failed admin logins detected from IP 10.0.0.5"
    )
    print(f"Is Duplicate? {is_dup}\n")
    
    # Test different semantics
    print("Testing different meaning:")
    is_dup2 = engine.evaluate_similarity(
        "Multiple failed admin logins detected from IP 10.0.0.5",
        "Ransomware encryption suspected on volume C:/"
    )
    print(f"Is Duplicate? {is_dup2}")
