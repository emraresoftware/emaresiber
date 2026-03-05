"""LLM Switch — cloud | onprem | hybrid otomatik seçim"""
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
import os


def get_llm(model_type: str = None, temperature: float = 0.0):
    """Otomatik LLM switch — .env'den LLM_MODE okur.

    LLM_MODE=cloud   → Claude-3.5-Sonnet (default)
    LLM_MODE=onprem  → Ollama (Llama3.3-70b)
    LLM_MODE=hybrid  → fast tasks: Groq, critical: Claude
    """
    mode = os.getenv("LLM_MODE", "cloud").lower()

    if mode == "onprem":
        try:
            from langchain_community.llms import Ollama
            return Ollama(
                model=os.getenv("OLLAMA_MODEL", "llama3.3:70b"),
                base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
                temperature=temperature,
            )
        except ImportError:
            raise ImportError("pip install langchain-community ollama")

    if mode == "hybrid":
        try:
            from langchain_groq import ChatGroq
            if model_type == "fast":
                return ChatGroq(model="gemma2-9b-it", temperature=temperature)
        except ImportError:
            pass
        return ChatAnthropic(
            model="claude-3-5-sonnet-20241022", temperature=temperature
        )

    # Default cloud
    return ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=temperature)


def get_vision_llm():
    """Vision/Multimodal LLM (Grok-4-Vision fallback to GPT-4o)"""
    return ChatOpenAI(
        model=os.getenv("VISION_MODEL", "gpt-4o"),
        max_tokens=1024,
    )
