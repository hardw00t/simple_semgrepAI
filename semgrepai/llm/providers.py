"""LLM provider configuration and factory."""
from typing import Optional, Dict, Any, Literal, Callable, List, Iterator
from pydantic import BaseModel, Field
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk
from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama
import time
import logging
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class CostMetrics:
    """Track costs for LLM API calls."""
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_requests: int = 0
    total_cost: float = 0.0
    failed_requests: int = 0
    retried_requests: int = 0
    total_latency: float = 0.0
    costs_by_model: Dict[str, float] = field(default_factory=dict)
    requests_by_model: Dict[str, int] = field(default_factory=dict)

    def add_request(self, model: str, input_tokens: int, output_tokens: int, cost: float, latency: float, failed: bool = False, retried: bool = False):
        """Record metrics for a single request."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_requests += 1
        self.total_cost += cost
        self.total_latency += latency

        if failed:
            self.failed_requests += 1
        if retried:
            self.retried_requests += 1

        if model not in self.costs_by_model:
            self.costs_by_model[model] = 0.0
            self.requests_by_model[model] = 0

        self.costs_by_model[model] += cost
        self.requests_by_model[model] += 1

    def save(self, path: Path):
        """Save metrics to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'total_input_tokens': self.total_input_tokens,
            'total_output_tokens': self.total_output_tokens,
            'total_requests': self.total_requests,
            'total_cost': self.total_cost,
            'failed_requests': self.failed_requests,
            'retried_requests': self.retried_requests,
            'total_latency': self.total_latency,
            'average_latency': self.total_latency / max(self.total_requests, 1),
            'costs_by_model': self.costs_by_model,
            'requests_by_model': self.requests_by_model,
            'timestamp': datetime.now().isoformat()
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: Path) -> 'CostMetrics':
        """Load metrics from JSON file."""
        if not path.exists():
            return cls()

        with open(path, 'r') as f:
            data = json.load(f)

        metrics = cls()
        metrics.total_input_tokens = data.get('total_input_tokens', 0)
        metrics.total_output_tokens = data.get('total_output_tokens', 0)
        metrics.total_requests = data.get('total_requests', 0)
        metrics.total_cost = data.get('total_cost', 0.0)
        metrics.failed_requests = data.get('failed_requests', 0)
        metrics.retried_requests = data.get('retried_requests', 0)
        metrics.total_latency = data.get('total_latency', 0.0)
        metrics.costs_by_model = data.get('costs_by_model', {})
        metrics.requests_by_model = data.get('requests_by_model', {})
        return metrics


class LLMProviderConfig(BaseModel):
    """Base configuration for LLM providers."""
    provider: Literal["openai", "anthropic", "openrouter", "ollama"] = "openai"
    model: str
    temperature: float = 0
    max_tokens: Optional[int] = None
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    extra_kwargs: Dict[str, Any] = Field(default_factory=dict)

    # Retry and rate limiting
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_exponential_backoff: bool = True
    max_retry_delay: float = 60.0
    rate_limit_requests_per_minute: Optional[int] = None
    rate_limit_tokens_per_minute: Optional[int] = None

    # Cost tracking
    enable_cost_tracking: bool = True
    cost_metrics_path: Optional[Path] = None

# Model pricing per 1M tokens (input/output) - Updated January 2026
MODEL_PRICING = {
    # OpenAI models
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
    "gpt-5": (15.00, 60.00),
    "gpt-5-mini": (5.00, 20.00),
    # Anthropic Claude 4.x models
    "claude-opus-4-5-20251101": (15.00, 75.00),
    "claude-sonnet-4-5-20250514": (3.00, 15.00),
    "claude-haiku-4-5-20250901": (0.80, 4.00),
    # Legacy models
    "gpt-4": (30.00, 60.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "claude-3-5-sonnet-latest": (3.00, 15.00),
    "claude-3-opus": (15.00, 75.00),
    "claude-3-haiku": (0.25, 1.25),
    # OpenRouter and Ollama models are free/self-hosted
    "ollama": (0.0, 0.0),
    "openrouter": (0.0, 0.0),
}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Calculate the cost of a request based on token usage."""
    # Get pricing, default to zero for unknown models
    pricing = MODEL_PRICING.get(model, (0.0, 0.0))
    input_cost = (input_tokens / 1_000_000) * pricing[0]
    output_cost = (output_tokens / 1_000_000) * pricing[1]
    return input_cost + output_cost


class ResilientLLMWrapper(Runnable):
    """Wrapper that adds retry logic and rate limiting to LLM calls.

    Implements the LangChain Runnable interface to work with LCEL chains.
    """

    def __init__(self, llm: BaseChatModel, config: LLMProviderConfig, cost_metrics: Optional[CostMetrics] = None):
        self.llm = llm
        self.config = config
        self.cost_metrics = cost_metrics
        self.last_request_time = 0.0
        self.tokens_used_this_minute = 0
        self.requests_this_minute = 0
        self.minute_start = time.time()

    @property
    def InputType(self):
        """Return the input type for this runnable."""
        return self.llm.InputType

    @property
    def OutputType(self):
        """Return the output type for this runnable."""
        return self.llm.OutputType

    def _check_rate_limits(self, estimated_tokens: int = 1000):
        """Check and enforce rate limits."""
        current_time = time.time()

        # Reset counters every minute
        if current_time - self.minute_start >= 60:
            self.tokens_used_this_minute = 0
            self.requests_this_minute = 0
            self.minute_start = current_time

        # Check request rate limit
        if self.config.rate_limit_requests_per_minute:
            if self.requests_this_minute >= self.config.rate_limit_requests_per_minute:
                sleep_time = 60 - (current_time - self.minute_start)
                if sleep_time > 0:
                    logger.warning(f"Rate limit reached. Sleeping for {sleep_time:.2f} seconds")
                    time.sleep(sleep_time)
                    self.tokens_used_this_minute = 0
                    self.requests_this_minute = 0
                    self.minute_start = time.time()

        # Check token rate limit
        if self.config.rate_limit_tokens_per_minute:
            if self.tokens_used_this_minute + estimated_tokens > self.config.rate_limit_tokens_per_minute:
                sleep_time = 60 - (current_time - self.minute_start)
                if sleep_time > 0:
                    logger.warning(f"Token rate limit reached. Sleeping for {sleep_time:.2f} seconds")
                    time.sleep(sleep_time)
                    self.tokens_used_this_minute = 0
                    self.requests_this_minute = 0
                    self.minute_start = time.time()

    def invoke(self, *args, **kwargs):
        """Invoke the LLM with retry logic and rate limiting."""
        retries = 0
        last_exception = None

        while retries <= self.config.max_retries:
            try:
                # Check rate limits before making request
                self._check_rate_limits()

                # Make the request
                start_time = time.time()
                result = self.llm.invoke(*args, **kwargs)
                latency = time.time() - start_time

                # Extract token usage and calculate cost
                input_tokens = 0
                output_tokens = 0
                if hasattr(result, 'response_metadata'):
                    usage = result.response_metadata.get('token_usage', {})
                    input_tokens = usage.get('prompt_tokens', 0)
                    output_tokens = usage.get('completion_tokens', 0)

                # Update rate limit counters
                self.requests_this_minute += 1
                self.tokens_used_this_minute += input_tokens + output_tokens

                # Track costs if enabled
                if self.cost_metrics and self.config.enable_cost_tracking:
                    cost = calculate_cost(self.config.model, input_tokens, output_tokens)
                    self.cost_metrics.add_request(
                        model=self.config.model,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        cost=cost,
                        latency=latency,
                        failed=False,
                        retried=(retries > 0)
                    )

                    # Save metrics periodically
                    if self.config.cost_metrics_path and self.cost_metrics.total_requests % 10 == 0:
                        self.cost_metrics.save(self.config.cost_metrics_path)

                logger.debug(f"LLM request successful (attempt {retries + 1}). Latency: {latency:.2f}s, Tokens: {input_tokens + output_tokens}")
                return result

            except Exception as e:
                last_exception = e
                retries += 1

                # Track failed request
                if self.cost_metrics and self.config.enable_cost_tracking:
                    self.cost_metrics.add_request(
                        model=self.config.model,
                        input_tokens=0,
                        output_tokens=0,
                        cost=0.0,
                        latency=0.0,
                        failed=True,
                        retried=True
                    )

                if retries > self.config.max_retries:
                    logger.error(f"LLM request failed after {retries} attempts: {e}")
                    raise

                # Calculate backoff delay
                if self.config.retry_exponential_backoff:
                    delay = min(self.config.retry_delay * (2 ** (retries - 1)), self.config.max_retry_delay)
                else:
                    delay = self.config.retry_delay

                logger.warning(f"LLM request failed (attempt {retries}). Retrying in {delay:.2f}s. Error: {e}")
                time.sleep(delay)

        raise last_exception


class LLMFactory:
    """Factory for creating LLM instances."""

    @staticmethod
    def create_llm(config: LLMProviderConfig, enable_resilience: bool = True) -> BaseChatModel:
        """Create an LLM instance based on the provider configuration."""
        common_kwargs = {
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            **config.extra_kwargs
        }

        if config.api_base:
            common_kwargs["base_url"] = config.api_base

        if config.api_key:
            common_kwargs["api_key"] = config.api_key

        # Create base LLM
        if config.provider == "openai":
            base_llm = ChatOpenAI(
                model_name=config.model,
                **common_kwargs
            )

        elif config.provider == "anthropic":
            base_llm = ChatAnthropic(
                model=config.model,
                **common_kwargs
            )

        elif config.provider == "openrouter":
            # OpenRouter uses OpenAI's API format
            base_llm = ChatOpenAI(
                model_name=config.model,
                base_url="https://openrouter.ai/api/v1",
                **common_kwargs
            )

        elif config.provider == "ollama":
            base_llm = ChatOllama(
                model=config.model,
                **common_kwargs
            )

        else:
            raise ValueError(f"Unsupported LLM provider: {config.provider}")

        # Wrap with resilience layer if enabled
        if enable_resilience:
            # Load or create cost metrics
            cost_metrics = None
            if config.enable_cost_tracking:
                metrics_path = config.cost_metrics_path or Path(".cache/llm/cost_metrics.json")
                cost_metrics = CostMetrics.load(metrics_path)
                config.cost_metrics_path = metrics_path

            return ResilientLLMWrapper(base_llm, config, cost_metrics)

        return base_llm

# Common model configurations
DEFAULT_MODELS = {
    "openai": {
        "gpt-4o": "General purpose model, good balance",
        "gpt-4.1": "Latest GPT-4 series, 1M context, best for coding",
        "gpt-4.1-mini": "Cost-effective GPT-4.1, 1M context",
        "o3": "Advanced reasoning model",
        "o4-mini": "Fast reasoning, excellent at math/coding",
        "gpt-5": "Latest flagship model",
        "gpt-5-mini": "Smaller flagship model",
    },
    "anthropic": {
        "claude-opus-4-5-20251101": "Most intelligent model, 200k context",
        "claude-sonnet-4-5-20250514": "Best for coding/agents, 1M context available",
        "claude-haiku-4-5-20250901": "Fastest, near-frontier performance",
    },
    "openrouter": {
        "anthropic/claude-opus-4-5": "Claude Opus 4.5 via OpenRouter",
        "anthropic/claude-sonnet-4-5": "Claude Sonnet 4.5 via OpenRouter",
        "anthropic/claude-haiku-4-5": "Claude Haiku 4.5 via OpenRouter",
        "openai/gpt-4.1": "GPT-4.1 via OpenRouter",
        "openai/o3": "o3 reasoning via OpenRouter",
        "google/gemini-2.0-flash": "Google Gemini 2.0 Flash via OpenRouter",
    },
    "ollama": {
        "mistral:latest": "Open source Mistral model",
        "llama3.3:latest": "Latest Llama 3.3 model",
        "deepseek-r1:14b": "DeepSeek R1 14b model",
        "qwen2.5-coder:latest": "Qwen 2.5 coding model",
        "nomic-embed-text:latest": "Nomic text embedding model",
    }
}
