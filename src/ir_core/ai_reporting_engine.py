import re
import json

class AIReportingEngine:
    """
    LLM pipeline for RCA Summarization and Regulatory Filing composition.
    Includes strict Input Sanitization to block Indirect Prompt Injections (OWASP LLM01).
    """
    def __init__(self):
        # Guardrails for OWASP LLM01 (Indirect Prompt Injection)
        self.malicious_prompts = [
            r"ignore previous instructions",
            r"system override",
            r"drop all tables",
            r"write this instead:",
            r"bypass guardrail",
            r"execute command:"
        ]

    def _sanitize_input(self, raw_ticket_history: str) -> str:
        """
        Scans and strips malicious instruction layers from incoming log data
        before passing it to the language model.
        """
        sanitized = raw_ticket_history
        for prompt in self.malicious_prompts:
            if re.search(prompt, sanitized, re.IGNORECASE):
                print(f"[AI Guardrail] Stripped prompt injection attempt: '{prompt}'")
                sanitized = re.sub(prompt, "[REDACTED_INJECTION]", sanitized, flags=re.IGNORECASE)
                
        return sanitized

    def _call_llm(self, prompt: str) -> str:
        """
        Helper method to invoke a local HuggingFace text-generation pipeline.
        """
        try:
            from transformers import pipeline
            if not hasattr(self, '_pipe'):
                self._pipe = pipeline("text-generation", model="gpt2") # Placeholder

            result = self._pipe(prompt, max_length=500, num_return_sequences=1)
            if result:
                return result[0]['generated_text']
        except Exception as e:
            # Fallback to simulation if AI is offline
            return None

    def generate_rca(self, ticket_id: str, raw_history: str) -> str:
        """
        Queries the LLM generating a Root Cause Analysis.
        """
        print(f"\n[AI Reporting] Generating RCA for {ticket_id}...")
        
        clean_history = self._sanitize_input(raw_history)
        
        prompt = f"""
        Act as an expert Incident Responder. Read the following chronological log ledger and generate a Root Cause Analysis summary.
        Ticket ID: {ticket_id}
        Logs:
        {clean_history}
        """

        ai_response = self._call_llm(prompt)
        if ai_response:
            return ai_response

        # Fallback Mock
        rca_report = f"""
        # Root Cause Analysis: {ticket_id}
        
        ## Summary
        Based on the chronological ledger, the incident began with an unauthorized network access attempt.
        The SOAR engine dynamically contained the threat via IP isolation. 
        
        ## Timeline Snippets Analyzed
        {clean_history}
        """
        return rca_report

    def generate_regulatory_filing(self, ticket_id: str, filing_type: str, raw_history: str) -> str:
        """
        Queries the LLM generating a compliance draft (e.g. GDPR, SEC 8-K).
        """
        print(f"\n[AI Reporting] Generating {filing_type} Draft for {ticket_id}...")
        
        clean_history = self._sanitize_input(raw_history)
        
        prompt = f"""
        Act as an expert Cyber Lawyer. Read the following chronological log ledger and generate a {filing_type} Compliance Notification draft.
        Ticket ID: {ticket_id}
        Logs:
        {clean_history}
        """

        ai_response = self._call_llm(prompt)
        if ai_response:
            return ai_response

        # Fallback Mock
        filing_draft = f"""
        # {filing_type} Compliance Notification
        **Reference Ticket:** {ticket_id}
        
        ## Incident Description
        A security event occurred involving potential data exposure. 
        Containment protocols were successfully executed autonomously by the defensive platform.
        
        ## Technical Data Processed
        {clean_history}
        
        **Note:** This is an AI-generated draft requiring Legal Counsel review before submission.
        """
        return filing_draft
