import time
import random
import json
import os

# --- Process/User/IP Pools ---
USERS = ["Alice", "Bob", "Charlie", "David"]
HOSTNAMES = ["DESKTOP-A1B2", "LAPTOP-X7Y8", "FINANCE-PC", "HR-STATION"]
MALWARE_NAMES = ["evil.exe", "updater.exe", "baddll.dll", "notvirus.exe"]
LEGIT_PROCESSES = ["explorer.exe", "winword.exe", "outlook.exe", "chrome.exe", "svchost.exe"]
CMD_SHELLS = ["cmd.exe", "powershell.exe"]
EXTERNAL_IPS = ["198.51.100.10", "203.0.113.25", "8.8.8.8", "1.1.1.1", "45.33.32.156"]
C2_IPS = ["1.2.3.4", "9.8.7.6", "100.101.102.103"]

# --- Helper Function ---
def generate_pid():
    return random.randint(1000, 9999)

def format_log(timestamp, event_type, hostname, user, process_name, pid, details):
    log_entry = {
        'timestamp': timestamp,
        'event': event_type,
        'hostname': hostname,
        'user': user,
        'process': process_name,
        'pid': pid,
    }
    log_entry.update(details)
    # Use json.dumps for consistent formatting, especially for nested structures
    return json.dumps(log_entry, sort_keys=True)

# --- Scenario Loading ---

SCENARIOS_FILE = os.path.join(os.path.dirname(__file__), "scenarios.json")

def load_scenarios():
    """Loads all scenarios from the scenarios.json file."""
    try:
        with open(SCENARIOS_FILE, 'r') as f:
            scenarios = json.load(f)
        # Basic validation (optional but good practice)
        if not isinstance(scenarios, list) or not all(isinstance(s, dict) for s in scenarios):
             print("Error: scenarios.json is not a list of dictionaries.")
             return []
        return scenarios
    except FileNotFoundError:
        print(f"Error: {SCENARIOS_FILE} not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {SCENARIOS_FILE}.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred loading scenarios: {e}")
        return []

# Load scenarios once when the module is imported
ALL_SCENARIOS = load_scenarios()

# --- Main Function ---

def get_challenge_data(difficulty=None):
    """Selects and returns a random challenge scenario based on difficulty."""
    if not ALL_SCENARIOS:
        # Return a default error message if no scenarios loaded
        return {
            "name": "Error Loading Scenario",
            "logs": ["Could not load scenarios from file. Please check scenarios.json and restart."],
            "questions": [],
            "mitre_hints": []
        }
    
    # Filter scenarios based on difficulty if provided
    filtered_scenarios = ALL_SCENARIOS
    if difficulty:
        filtered_scenarios = [s for s in ALL_SCENARIOS if s.get('difficulty') == difficulty]

    if not filtered_scenarios:
         # Fallback or error if no scenarios match the difficulty
        return {
            "name": f"Error: No '{difficulty}' Scenarios",
            "logs": [f"Could not find any scenarios matching difficulty '{difficulty}'. Please check scenarios.json."],
            "questions": [],
            "mitre_hints": []
        }

    # Choose a random scenario from the filtered list
    chosen_scenario = random.choice(filtered_scenarios)

    # Ensure the chosen scenario has the expected keys (optional safety check)
    # We rely on the JSON structure being correct, but could add checks here.

    return chosen_scenario

# --- Example Usage (Optional) ---
if __name__ == "__main__":
    # Test loading scenarios
    print(f"Loaded {len(ALL_SCENARIOS)} scenarios.")
    if ALL_SCENARIOS:
        print("\nExample Basic Scenario:")
        basic_challenge = get_challenge_data(difficulty='basic')
        if 'Error' not in basic_challenge.get('name', ''):
            print(f"  Name: {basic_challenge.get('name')}")
            # ... print details ...
        else:
            print(f"  {basic_challenge.get('logs', ['Error message missing.'])[0]}")

        print("\nExample Advanced Scenario:")
        advanced_challenge = get_challenge_data(difficulty='advanced')
        if 'Error' not in advanced_challenge.get('name', ''):
            print(f"  Name: {advanced_challenge.get('name')}")
            # ... print details ...
        else:
             print(f"  {advanced_challenge.get('logs', ['Error message missing.'])[0]}")
        
        # Keep the original example for general testing if needed
        # print("\nExample Random Scenario (any difficulty):")
        # challenge = get_challenge_data() 
        # ... original print logic ...

# The following lines demonstrating printing logs, questions, mitre hints are omitted for brevity
# but should be updated similarly if you want to test specific difficulties here.
