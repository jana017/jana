"""NivX HealthBot subsystem.

Runs a fleet of health probes across the app and repairs the deterministic
subset. **Zero dependency on any LLM** — every check + fix is pure Python
stdlib / motor / existing backend modules, so it keeps working identically
after the app is transferred to any VPS.
"""
