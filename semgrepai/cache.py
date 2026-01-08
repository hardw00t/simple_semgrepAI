from pathlib import Path
import json
import hashlib
from typing import Dict, Any, Optional
import os
from datetime import datetime, timedelta

class ValidationCache:
    """Cache for storing validation results to avoid redundant LLM calls."""
    
    def __init__(self, cache_dir: Path):
        """Initialize the validation cache.
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "validation_cache.json"
        self._load_cache()

    def _load_cache(self):
        """Load the cache from disk."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            except json.JSONDecodeError:
                self.cache = {}
        else:
            self.cache = {}

    def _save_cache(self):
        """Save the cache to disk."""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a cached validation result.
        
        Args:
            key: Cache key
            
        Returns:
            Cached validation result or None if not found
        """
        if key in self.cache:
            return self.cache[key]
        return None

    def set(self, key: str, value: Dict[str, Any]):
        """Set a validation result in the cache.
        
        Args:
            key: Cache key
            value: Validation result to cache
        """
        self.cache[key] = value
        self._save_cache()

    def clear(self):
        """Clear the cache."""
        self.cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()