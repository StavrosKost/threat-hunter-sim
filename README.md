# Threat Hunter Simulator

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io/) <!-- Optional: Replace with your deployed app URL if using Streamlit Community Cloud -->

## Description

This project is a Streamlit-based simulator designed to help users practice analyzing security log data and identifying malicious activities based on simulated attack scenarios. Users can load basic or advanced challenges, filter logs, identify entities, answer questions, and learn about relevant MITRE ATT&CK techniques.

## Features

*   **Multiple Scenarios:** Includes various basic and advanced attack scenarios defined in `scenarios.json`.
*   **Interactive Log Analysis:**
    *   Filter logs by Timestamp, Hostname (Advanced), EventID, Process, and Details.
    *   Filter logs by date/time range.
    *   Correlate logs by Process ID (PID).
    *   Highlight search terms within logs.
*   **Entity Extraction:** Automatically identifies and displays potential IPs, Domains, Files, and Processes found in filtered logs.
*   **MITRE ATT&CK Integration:**
    *   **Scenario Hints:** Provides curated MITRE ATT&CK techniques relevant to the overall scenario narrative (Solution).
    *   **Potential Techniques:** Dynamically suggests potential techniques based on rules applied to filtered logs (Analysis Aid).
*   **Q&A and Scoring:** Answer questions based on log analysis and receive immediate feedback with scoring and time tracking.
*   **Enhanced Feedback:** Shows relevant log snippets and MITRE hints related to incorrectly answered questions (requires population in `scenarios.json`).
*   **Beginner's Guide:** An in-app guide explaining the simulator's interface and basic log analysis concepts.
*   **Notepad:** A simple in-app notepad for jotting down findings during a challenge.
*   **Scoreboard:** Tracks top scores locally in `scoreboard.json`.

## Requirements

*   Python 3.8+
*   Libraries listed in `requirements.txt` (`streamlit`, `pandas`)

## Installation & Running

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd threat-hunter-simulator # Or your repository name
    ```
2.  **Create a virtual environment (Recommended):**
    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the Streamlit app:**
    ```bash
    streamlit run streamlit_app.py
    ```

The application should open automatically in your web browser.

## Files

*   `streamlit_app.py`: The main Streamlit application code.
*   `threat_bot.py`: Helper module for loading challenge data.
*   `scenarios.json`: Contains the definitions for all attack scenarios (logs, questions, hints).
*   `mitre_mapping.json`: Defines rules for mapping log patterns to potential MITRE techniques.
*   `requirements.txt`: Lists Python dependencies.
*   `scoreboard.json`: Stores local high scores (created on first save).
*   `.gitignore`: Specifies files/directories for Git to ignore.
*   `README.md`: This file.

## Future Enhancements (Ideas)

*   Add more diverse and complex scenarios.
*   Implement log timeline visualization.
*   Refine and expand the MITRE technique suggestion rules.
*   Add support for different log formats (e.g., JSON logs).
*   Integrate external lookups (e.g., VirusTotal) for entities.
