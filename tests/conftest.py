"""Expose v0.1 only to compatibility tests, never to the shipped runtime."""
from pathlib import Path
import sys

import tooluseproxy
import tooluseproxy.integrations

legacy = Path(__file__).resolve().parents[1] / 'legacy' / 'v0.1'
sys.path.append(str(legacy))
tooluseproxy.__path__.append(str(legacy / 'tooluseproxy'))
tooluseproxy.integrations.__path__.append(str(legacy / 'tooluseproxy' / 'integrations'))
