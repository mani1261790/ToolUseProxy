"""Compatibility entry point for the packaged ToolUseProxy log viewer."""
from tooluseproxy.log_viewer import LogReader, PAYLOAD_LIMIT, make_server, main

__all__ = ["LogReader", "PAYLOAD_LIMIT", "make_server", "main"]

if __name__ == "__main__":
    main()
