import logging

logger = logging.getLogger("AIClassifier")

class LocalAIClassifier:
    """
    Singleton manager for loading HuggingFace models directly into Python memory.
    Using lazy loading so the heavy models aren't loaded until they are actually needed.
    """
    _pipeline = None

    @classmethod
    def get_pipeline(cls):
        if cls._pipeline is None:
            try:
                logger.info("Loading HuggingFace model: MattP30098638/PenTest-AI...")
                # We wrap the import here so the entire platform doesn't crash if 'transformers' isn't installed yet
                from transformers import pipeline

                # Load the classification pipeline directly
                cls._pipeline = pipeline("text-classification", model="MattP30098638/PenTest-AI")
                logger.info("HuggingFace model loaded successfully.")

            except ImportError:
                logger.warning("The 'transformers' library is not installed. AI Classification will be bypassed.")
                return None
            except Exception as e:
                logger.error(f"Failed to load HuggingFace model: {e}")
                return None

        return cls._pipeline

    @classmethod
    def classify_log(cls, log_text: str) -> dict:
        """
        Passes the log text into the local AI model.
        Returns the classification result (e.g. {'label': 'MALICIOUS', 'score': 0.99})
        """
        pipe = cls.get_pipeline()
        if not pipe:
            return None

        try:
            # The pipeline usually returns a list of dicts: [{'label': '...', 'score': ...}]
            result = pipe(log_text)
            if result and isinstance(result, list):
                return result[0]
        except Exception as e:
            logger.error(f"Error during AI classification inference: {e}")

        return None
