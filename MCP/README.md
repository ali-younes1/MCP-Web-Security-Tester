# MCP Web Security Tester

Python MCP server that connects Claude Desktop with a Playwright browser for authorized web security testing.

The project lets an AI open web pages, interact with forms, test one payload at a time, and collect evidence by comparing the normal page behavior with the test result.

It is mainly focused on:

SQL injection testing
NoSQL injection testing
XSS testing
Browser-based evidence collection
Baseline vs test response comparison

Instead of using a fixed payload library, the LLM generates payloads during testing, analyzes the results, and adapts its next steps based on the evidence returned by the tool.

The design can be extended later with more guided testing strategies and vulnerability categories.

## Tech Stack

Python
Model Context Protocol SDK
FastMCP
Playwright

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

On Windows PowerShell:

```bash
.\.venv\Scripts\activate
```

Install dependencies:

```bash
pip install "mcp[cli]" playwright
```

Install the Playwright Chromium browser:

```bash
python -m playwright install chromium
```

Run the server:

```bash
python server.py
```

## Claude Desktop Configuration

Add the MCP server to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "mcp-security": {
      "command": "C:\\Users\\PC\\OneDrive - ESPRIT\\Bureau\\mcp-python\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\PC\\OneDrive - ESPRIT\\Bureau\\mcp-python\\MCP\\server.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

Replace the paths with the location of your cloned project.

Restart Claude Desktop after saving the configuration.
