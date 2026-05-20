# HCP Stealth Fuzzer & Command Center

A high-performance, distributed web fuzzing framework designed for stealthy enumeration and vulnerability discovery. Built for Slurm clusters with a modern AJAX-driven Command Center.

## Key Features

*   **Distributed Fuzzing:** Orchestrated via Slurm (`srun`/`sbatch`) across multiple cluster nodes.
*   **Command Center UI:** A high-density "HUD" style dashboard for real-time monitoring and control.
*   **AJAX-Powered Live Preview:** Seamlessly view discoveries and logs without page reloads.
*   **Advanced Fuzzing Modes:**
    *   **Subdomain Fuzzing:** Discover virtual hosts via `Host` header manipulation.
    *   **API Fuzzing:** Probe for REST, JSON, and GraphQL endpoints.
    *   **Parameter Fuzzing:** Find hidden GET/POST parameters.
    *   **Method Fuzzing:** Cycle through HTTP verbs (PUT, DELETE, OPTIONS, etc.).
    *   **Header Injection:** Bypass firewalls and auth with custom headers.
*   **AI-Powered Analysis:** Integrated LLM (Llama 3) for automated log analysis and security audits.
*   **Stealth Mechanisms:**
    *   Adaptive rate limiting with jitter.
    *   Proxy rotation and distribution layer.
    *   WAF evasion through query parameter randomization.
    *   Advanced Soft-404 detection and auto-calibration.

## Architecture

*   `stealth_fuzzer`: The core Go engine responsible for high-speed request generation.
*   `results_server`: The Go-based dashboard and API provider.
*   `run_fuzz.sh`: The cluster orchestrator script.

## Getting Started

1.  Configure your target URL and status filters in the Command Center.
2.  Select a wordlist from the pre-loaded options.
3.  Choose your desired Advanced Fuzzing Modes.
4.  Launch the campaign and watch the real-time terminal.

---
*Created for the HCP Cluster Environment.*
