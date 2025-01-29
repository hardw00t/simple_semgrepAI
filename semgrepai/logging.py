import logging
import logging.config
import yaml
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler
import sys

def setup_logging(
    config_path: Optional[Path] = None,
    default_level: int = logging.INFO,
    log_file: Optional[Path] = None
) -> None:
    """
    Set up logging configuration for the application.
    
    Args:
        config_path: Path to logging config YAML file
        default_level: Default logging level if config file not found
        log_file: Path to log file. If None, only console logging is enabled
    """
    if config_path and config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
            
        # If log_file is provided, update file handler path
        if log_file and 'handlers' in config:
            for handler in config['handlers'].values():
                if handler.get('class') == 'logging.FileHandler':
                    handler['filename'] = str(log_file)
        
        logging.config.dictConfig(config)
    else:
        # Default logging configuration
        handlers = [
            RichHandler(
                rich_tracebacks=True,
                markup=True,
                show_time=True,
                show_path=True
            )
        ]
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            handlers.append(file_handler)
        
        logging.basicConfig(
            level=default_level,
            handlers=handlers,
            format="%(message)s",
        )

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)
