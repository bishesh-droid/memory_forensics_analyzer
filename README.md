# Memory Forensics Analyzer

This project provides a comprehensive tool for analyzing memory dumps to identify potential malware, malicious activities, and system anomalies. It leverages various plugins to extract crucial forensic artifacts such as running processes, network connections, loaded modules, and more, from memory images.

## Features

*   **Process Listing (`pslist`):** Identify active and terminated processes.
*   **Network Connections (`netscan`):** Detect established network connections and listening ports.
*   **Module Listing (`modscan`):** Enumerate loaded kernel modules and user-mode DLLs.
*   **Extensible Plugin Architecture:** Easily add new forensic analysis capabilities through a modular plugin system.
*   **User-friendly Command-Line Interface:** Simple execution and reporting of analysis results.

## Installation

### Prerequisites

*   Python 3.x
*   Volatility Framework (or similar memory forensics tool to generate memory dumps)

### Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/memory_forensics_analyzer.git
    cd memory_forensics_analyzer
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    pip install -e .
    ```

## Usage

To use the memory forensics analyzer, you will need a memory dump file (e.g., a `.bin` or `.vmem` file).

You can run the analyzer either as a Python module or using the installed command-line script.

### Using the Command-Line Script (Recommended)

After installation, you can use the `mem-analyze` script:

```bash
mem-analyze --file <path_to_memory_dump> --command <plugin_name>
```

### Basic Execution

```bash
python -m memory_forensics_analyzer.main --file <path_to_memory_dump> --command <plugin_name>
```

### Examples

*   **List processes:**
    ```bash
    mem-analyze --file /path/to/memory_dump.raw --command pslist
    ```

*   **Scan network connections:**
    ```bash
    mem-analyze --file /path/to/memory_dump.raw --command netscan
    ```

*   **List loaded modules:**
    ```bash
    mem-analyze --file /path/to/memory_dump.raw --command modscan
    ```

## Project Structure

```
.
├── memory_forensics_analyzer/
│   ├── __init__.py
│   ├── main.py             # Main entry point for the analyzer
│   ├── utils.py            # Utility functions (e.g., for parsing, reporting)
│   └── plugins/            # Directory for forensic analysis plugins
│       ├── __init__.py
│       ├── modscan_plugin.py
│       ├── netscan_plugin.py
│       └── pslist_plugin.py
├── requirements.txt      # Python dependencies
├── setup.py              # Project setup file
├── tests/                # Unit and integration tests
└── README.md             # This file
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License. See the `LICENSE` file in the `MemLabs` directory for more details.