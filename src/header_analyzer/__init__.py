"""header-analyzer: audit a website's HTTP security headers."""

from .scanner import analyse
from .models import Finding

__version__ = "1.0.0"
__all__ = ["analyse", "Finding", "__version__"]
