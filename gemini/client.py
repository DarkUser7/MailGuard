import os
from dotenv import load_dotenv

load_dotenv()


class GeminiClient:
    """Client for Google Gemini AI API."""

    def __init__(self, api_key: str | None = None):
        if api_key is not None:
            self.api_key = api_key
        else:
            # Prefer Streamlit secrets, fall back to env var
            try:
                import streamlit as st
                self.api_key = st.secrets.get("GEMINI_API_KEY") or os.getenv("GEMINI_API_KEY")
            except Exception:
                self.api_key = os.getenv("GEMINI_API_KEY")
        self.client = None
        self.model_name = 'gemini-2.5-flash'
        
        if self.api_key and self.api_key.strip() and self.api_key != 'your_api_key_here':
            self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the Gemini client."""
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except ImportError:
            print("Warning: google-genai package not installed. Install with: pip install google-genai")
            self.client = None
        except Exception as e:
            print(f"Warning: Failed to initialize Gemini client: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if Gemini client is available."""
        return self.client is not None
    
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generate content using Gemini."""
        if not self.is_available():
            raise ConnectionError("Gemini client is not available. Check your API key.")
        
        try:
            contents = prompt
            config = None
            
            if system_prompt:
                from google.genai import types
                config = types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.3,  # Low temperature for consistent reports
                    max_output_tokens=2048
                )
            
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config
            )
            
            return response.text
            
        except Exception as e:
            raise RuntimeError(f"Gemini generation failed: {e}")
