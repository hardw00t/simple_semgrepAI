"""LLM provider configuration and factory."""
from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama

class LLMProviderConfig(BaseModel):
    """Base configuration for LLM providers."""
    provider: Literal["openai", "anthropic", "openrouter", "ollama"] = "openai"
    model: str
    temperature: float = 0
    max_tokens: Optional[int] = None
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    extra_kwargs: Dict[str, Any] = Field(default_factory=dict)

class LLMFactory:
    """Factory for creating LLM instances."""
    
    @staticmethod
    def create_llm(config: LLMProviderConfig) -> BaseChatModel:
        """Create an LLM instance based on the provider configuration."""
        common_kwargs = {
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            **config.extra_kwargs
        }
        
        if config.api_base:
            common_kwargs["api_base"] = config.api_base
            
        if config.api_key:
            common_kwargs["api_key"] = config.api_key
            
        if config.provider == "openai":
            return ChatOpenAI(
                model_name=config.model,
                **common_kwargs
            )
            
        elif config.provider == "anthropic":
            return ChatAnthropic(
                model=config.model,
                **common_kwargs
            )
            
        elif config.provider == "openrouter":
            # OpenRouter uses OpenAI's API format
            return ChatOpenAI(
                model_name=config.model,
                api_base="https://openrouter.ai/api/v1",
                **common_kwargs
            )
            
        elif config.provider == "ollama":
            return ChatOllama(
                model=config.model,
                **common_kwargs
            )
            
        raise ValueError(f"Unsupported LLM provider: {config.provider}")

# Common model configurations
DEFAULT_MODELS = {
    "openai": {
        "gpt-4o": "Most capable OpenAI model, best for complex tasks",
        "gpt-3.5-turbo": "Good balance of capability and speed",
    },
    "anthropic": {
        "claude-3-opus": "Most capable Anthropic model",
        "claude-3-sonnet": "Good balance of capability and speed",
        "claude-3-haiku": "Fast and efficient",
    },
    "openrouter": {
        "anthropic/claude-3-opus": "Claude 3 Opus via OpenRouter",
        "anthropic/claude-3-sonnet": "Claude 3 Sonnet via OpenRouter",
        "google/gemini-pro": "Google's Gemini Pro via OpenRouter",
    },
    "ollama": {
        "mistral:latest": "Open source Mistral model",
        "llama3.1:latest": "Latest Llama 3.1 model",
        "deepseek-r1:14b": "DeepSeek R1 14b model",
        "nomic-embed-text:latest": "Nomic text embedding model"
    }
}
