"""Shared hard limits for live capture and untrusted offline trace input."""

# Complex pages need room for bounded request stacks as well as source text.
# This is not a per-event limit; message, event and source caps remain separate.
MAX_RAW_BYTES = 1024 * 1024
MAX_COMMANDS = 128
