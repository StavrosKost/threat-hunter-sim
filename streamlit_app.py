import streamlit as st
import threat_bot
import time
import json
import os
from datetime import timedelta, datetime
from datetime import time as dt_time
import re # Import re for parsing
import pandas as pd # Add pandas
import altair as alt # Add altair

# --- Page Config (MUST BE FIRST STREAMLIT COMMAND) ---
st.set_page_config(page_title="Threat Hunter Sim", layout="wide")

# --- Constants ---
SCOREBOARD_FILE = "scoreboard.json"
MITRE_MAPPING_FILE = "mitre_mapping.json" # Added constant

# --- Load MITRE Mapping --- 
@st.cache_data # Cache the mapping data
def load_mitre_mapping():
    """Loads the MITRE mapping rules from the JSON file."""
    if not os.path.exists(MITRE_MAPPING_FILE):
        # Use st.warning or st.error, but ensure page config is already set
        st.warning(f"Warning: {MITRE_MAPPING_FILE} not found! Using empty rules.")
        return []
    try:
        with open(MITRE_MAPPING_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, IOError) as e:
        st.error(f"Error loading {MITRE_MAPPING_FILE}: {e}")
        return []

mitre_rules = load_mitre_mapping() # Load it once

# --- Session State Initialization ---
if 'app_mode' not in st.session_state: st.session_state.app_mode = "Simulator"
if 'challenge_loaded' not in st.session_state:
    st.session_state.challenge_loaded = False
if 'challenge_data' not in st.session_state:
    st.session_state.challenge_data = {'logs': [], 'questions': [], 'mitre_hints': []}
if 'user_answers' not in st.session_state:
    st.session_state.user_answers = {}
if 'results' not in st.session_state:
    st.session_state.results = None
if 'start_time' not in st.session_state:
    st.session_state.start_time = None
if 'user_name' not in st.session_state:
    st.session_state.user_name = ""
if 'score_saved' not in st.session_state:
    st.session_state.score_saved = False
if 'log_search_term' not in st.session_state:
    st.session_state.log_search_term = ""
if 'ts_search' not in st.session_state: st.session_state.ts_search = ""
if 'host_search' not in st.session_state: st.session_state.host_search = ""
if 'eventid_search' not in st.session_state: st.session_state.eventid_search = "Any"
if 'proc_search' not in st.session_state: st.session_state.proc_search = ""
if 'details_search' not in st.session_state: st.session_state.details_search = ""
# Initialize date/time filters
if 'start_date_filter' not in st.session_state: st.session_state.start_date_filter = None
if 'start_time_filter' not in st.session_state: st.session_state.start_time_filter = None
if 'end_date_filter' not in st.session_state: st.session_state.end_date_filter = None
if 'end_time_filter' not in st.session_state: st.session_state.end_time_filter = None
if 'correlation_pid' not in st.session_state: st.session_state.correlation_pid = None # Added for PID correlation
if 'log_to_copy' not in st.session_state: st.session_state.log_to_copy = None # Added state for copying
if 'user_notes' not in st.session_state: st.session_state.user_notes = "" # Added for notes

# --- Main Functions ---
def load_challenge(difficulty='basic'):
    """Loads a new challenge into session state based on difficulty and starts the timer."""
    challenge_data = threat_bot.get_challenge_data(difficulty=difficulty)
    st.session_state.challenge_data = challenge_data
    st.session_state.user_answers = {str(q['id']): "" for q in st.session_state.challenge_data.get('questions', [])}
    st.session_state.results = None
    st.session_state.challenge_loaded = True
    st.session_state.start_time = time.time()
    st.session_state.score_saved = False
    st.session_state.user_notes = "" # Reset notes on new challenge

def calculate_score():
    """Calculates score based on user answers in session state. Called on submit."""
    score = 0
    results_details = {}
    questions = st.session_state.challenge_data.get('questions', [])
    for q in questions:
        q_id = str(q['id'])
        correct_answer_raw = q['answer'] # Keep original casing for display
        user_answer = st.session_state.user_answers.get(q_id, '').strip()

        # --- Modified Answer Checking Logic ---
        correct_answer_lower = correct_answer_raw.lower()
        user_answer_lower = user_answer.lower()
        is_correct = False # Default to false

        if " or " in correct_answer_lower:
            # Handle multiple correct options separated by " or "
            possible_answers = [ans.strip() for ans in correct_answer_lower.split(" or ")]
            if user_answer_lower in possible_answers:
                is_correct = True
        else:
            # Standard exact match comparison (case-insensitive)
            if user_answer_lower == correct_answer_lower:
                is_correct = True
        # --- End Modified Logic ---

        if is_correct: score += 1
        details = {
            'question_text': q['text'], 'correct': is_correct,
            'user_answer': user_answer, # Store user's original input
            'correct_answer': correct_answer_raw # Store original correct answer string for display
        }
        if 'relevant_log_indices' in q: details['relevant_log_indices'] = q['relevant_log_indices']
        if 'relevant_mitre_indices' in q: details['relevant_mitre_indices'] = q['relevant_mitre_indices']
        results_details[q_id] = details
    st.session_state.results = {'score': score, 'total': len(questions), 'details': results_details}
    st.session_state.end_time = time.time()

def load_scores():
    """Loads scores from the JSON file."""
    if not os.path.exists(SCOREBOARD_FILE): return []
    try:
        with open(SCOREBOARD_FILE, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError): return []

def save_score(name, score, total, time_taken):
    """Adds a score entry and saves to the JSON file."""
    scores = load_scores()
    scores.append({
        'name': name, 'score': score, 'total': total,
        'time': round(time_taken), 'timestamp': time.time()
    })
    scores.sort(key=lambda x: (-x['score'], x['time']))
    try:
        with open(SCOREBOARD_FILE, 'w') as f: json.dump(scores, f, indent=4)
        st.session_state.score_saved = True
        return True
    except IOError as e:
        st.error(f"Error saving scoreboard: {e}")
        return False

# --- Helper Functions ---
def parse_log(log_string):
    """Attempts to parse a log string into a dictionary.
       Tries JSON first, then pipe-separated key:value pairs.
    """
    log_data = {}
    try:
        # Attempt to parse as JSON first
        log_data = json.loads(log_string)
        # Convert keys to consistent casing (optional, but helpful)
        log_data = {k.lower().replace(" ", "_"): v for k, v in log_data.items()}
        # Ensure pid is extracted if present in JSON
        if 'processid' in log_data: # Example common key for pid
             log_data['pid'] = log_data.pop('processid')
        return log_data
    except json.JSONDecodeError:
        # If not JSON, try pipe-separated format
        try:
            parts = log_string.split('|')
            for part in parts:
                key_value = part.split(':', 1) # Split only on the first colon
                if len(key_value) == 2:
                    key = key_value[0].strip().lower().replace(" ", "_")
                    value = key_value[1].strip()
                    # Explicitly check for pid keys
                    if key in ['pid', 'processid', 'process_id']:
                         log_data['pid'] = value # Standardize key
                         # Don't add it again below if we standardise
                         continue 
                    # Handle potential nested structures represented as strings (basic handling)
                    if value.startswith('{') and value.endswith('}'):
                         # Simple attempt to make it look like a dict string
                         value = value.replace('=', ': ') 
                    log_data[key] = value
            return log_data
        except Exception as e:
            # If pipe parsing fails, return raw string under a 'raw' key
            # print(f"Failed to parse log part: {part}. Error: {e}") # Optional debug print
            return {'raw': log_string, 'pid': None} 
    except Exception as e:
        # Catch any other unexpected errors during parsing
        # print(f"General parsing error: {e}") # Optional debug print
        return {'raw': log_string, 'pid': None} 

def highlight_matches(text, filter_term):
    """Wraps case-insensitive matches of filter_term in text with <mark> tags."""
    if not filter_term: # If filter is empty, return original text
        return text
    try:
        # Find all non-overlapping matches, case-insensitive
        matches = re.finditer(re.escape(filter_term), text, re.IGNORECASE)
        highlighted_text = ""
        last_end = 0
        for match in matches:
            start, end = match.span()
            highlighted_text += text[last_end:start] # Add text before match
            highlighted_text += f"<mark>{text[start:end]}</mark>" # Add highlighted match
            last_end = end
        highlighted_text += text[last_end:] # Add text after the last match
        return highlighted_text
    except re.error:
         # Handle potential regex errors with invalid filter terms
         return text # Return original text if regex fails

def extract_entities(text):
    """Extracts potential IPs, domains, files, and processes using regex."""
    entities = {
        'ips': set(),
        'domains': set(),
        'files': set(),
        'processes': set() # Added processes set
    }
    
    # Basic IP Address Regex (v4)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    # Basic Domain Name Regex (simple version)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # Combine file/process patterns
    file_pattern = r'\b(?:[a-zA-Z]:\\|[\\\\]|\.\\|\/|C:\\)[^\\/:*?"<>|\s]+\.(?:exe|dll|ps1|bat|vbs|js|docm|docx|xlsx|pptx|zip|rar|dmp|txt)\b'
    # Simpler pattern for filenames/processes (common extensions)
    process_file_pattern = r'\b[a-zA-Z0-9_.-]+\.(?:exe|dll|ps1|bat|vbs|js|docm|docx|xlsx|pptx|zip|rar|dmp|txt)\b'
    
    common_file_extensions = {'.exe', '.dll', '.ps1', '.bat', '.vbs', '.js', '.docm', '.docx', '.xlsx', '.pptx', '.zip', '.rar', '.dmp', '.txt'}

    try:
        entities['ips'].update(re.findall(ip_pattern, text))
        # Filter out common non-routable/local IPs if desired (optional)
        # entities['ips'] = {ip for ip in entities['ips'] if not ip.startswith(('192.168.', '10.', '172.16.', '127.0.0.1'))} 
        
        potential_domains = set(re.findall(domain_pattern, text))
        # --- Filter out domains that look like filenames --- 
        actual_domains = set()
        for domain in potential_domains:
            # Check if domain ends with a common extension after converting to lower
            matched_extension = False
            for ext in common_file_extensions:
                if domain.lower().endswith(ext):
                    matched_extension = True
                    break
            if not matched_extension and '.' in domain and len(domain) > 3:
                 actual_domains.add(domain) # Only add if it doesn't end with a known file extension
        entities['domains'] = actual_domains
        # --- End domain filtering ---

        # Extract files and processes
        found_files_processes = set(re.findall(file_pattern, text, re.IGNORECASE))
        found_files_processes.update(re.findall(process_file_pattern, text, re.IGNORECASE))
        
        for item in found_files_processes:
            cleaned_item = item.strip('"\'')
            if cleaned_item.lower().endswith('.exe'):
                 entities['processes'].add(cleaned_item)
            else:
                 # Add other file types if they don't look like domains we already captured
                 if cleaned_item not in entities['domains']:
                      entities['files'].add(cleaned_item) 

    except Exception as e:
        # print(f"Regex error: {e}") # Optional debug
        pass
        
    return entities

# --- Callback Function for Clearing Filters ---
def clear_all_filters():
    keys_to_clear = [
        "ts_search", "proc_search", "details_search",
        "start_date_filter", "start_time_filter", "end_date_filter", "end_time_filter"
    ]
    select_keys_to_reset = ["eventid_search"]
    
    if st.session_state.get('challenge_data', {}).get('difficulty') == 'advanced':
         if "host_search" in st.session_state: # Check if key exists before adding
            keys_to_clear.append("host_search") 
            select_keys_to_reset.append("host_search")
    
    for key in keys_to_clear:
        if key in st.session_state:
            st.session_state[key] = None if "date" in key or "time" in key else ""
            
    for key in select_keys_to_reset:
        if key in st.session_state:
             st.session_state[key] = "Any" 
             
    # Also clear the correlation PID
    st.session_state.correlation_pid = None # Reset to None

# --- New Callback Function for Setting Correlation PID ---
def set_correlation_pid(pid):
    """Sets the correlation PID in session state."""
    st.session_state.correlation_pid = pid

# --- Beginner's Guide Content Function ---
def display_guide():
    st.title("🔰 Beginner's Guide to the Threat Hunter Sim")
    st.markdown("Welcome! This guide helps you get started with analyzing logs and using the simulator.")

    st.header("What is this Simulator?")
    st.markdown("This tool simulates security scenarios based on real-world attack techniques. By examining sequences of log events, you can practice:")
    st.markdown("- **Identifying suspicious activity:** Learn to spot unusual process behavior, network connections, or system changes.")
    st.markdown("- **Understanding attack patterns:** See how attackers chain different actions together to achieve their goals.")
    st.markdown("- **Applying MITRE ATT&CK:** Connect observed activities to known adversary Tactics, Techniques, and Procedures (TTPs).")
    st.markdown("The goal is to analyze the provided logs and answer questions about the simulated incident.")

    st.header("Understanding the Interface")
    st.markdown("**Sidebar (Left):**")
    st.markdown("- **Mode Selection:** Switch between this Guide and the Simulator.")
    st.markdown("- **Challenge Buttons:** Start a **Basic** (fewer logs, simpler attack) or **Advanced** (more logs, complex attack) scenario.")
    st.markdown("- **Timer:** Shows time elapsed while a challenge is active, or the final time upon submission.")
    st.markdown("- **Scoreboard:** Displays top scores achieved by users.")
    st.markdown("**Main Area (Center):**")
    st.markdown("- **Scenario Logs:** This is where the simulated log entries appear. This is your primary data source.")
    st.markdown("- **Log Filters:** Tools to help you search and analyze the logs (more below)." )
    st.markdown("- **Log Timeline:** A chart showing when logs occurred, useful for spotting bursts of activity.")
    st.markdown("- **Extracted Entities:** Automatically identified IPs, Domains, Files, and Processes found in the *currently filtered* logs.")
    st.markdown("- **Questions:** The questions you need to answer based on your analysis of the logs.")
    st.markdown("- **MITRE Hints (Expander):** Click to reveal hints related to potential MITRE ATT&CK techniques seen in the scenario.")
    st.markdown("- **Results:** After submitting your answers, this section shows your score, time, and correct/incorrect answers with feedback.")

    st.header("Basic Log Analysis Concepts")
    st.markdown("Logs record events that happen on a system. Key fields often include:")
    st.markdown("- **Timestamp:** When the event occurred (usually YYYY-MM-DD HH:MM:SS). Critical for sequencing events.")
    st.markdown("- **Hostname/SourceComputer:** The name of the computer where the event happened.")
    st.markdown("- **EventID:** A numerical code identifying the type of event (e.g., Windows Event ID 4688 for Process Creation, Sysmon Event ID 3 for Network Connection).")
    st.markdown("- **Process/Image:** The name of the program/executable involved (e.g., `powershell.exe`, `svchost.exe`).")
    st.markdown("- **CommandLine/Process Command Line:** The exact command executed by a process. Often reveals malicious intent.")
    st.markdown("- **ParentProcess:** The process that launched the current process.")
    st.markdown("- **NetworkConnection:** Details for network events, like Destination IP/Port, Source IP/Port, Protocol (TCP/UDP/ICMP).")
    st.markdown("- **TargetFilename/ObjectName:** The file or object being accessed or modified.")
    st.markdown("**Example Breakdown:**")
    st.code("Timestamp: 2023-10-26 10:05:38 | EventID: 4688 | Process: POWERSHELL.EXE | CommandLine: powershell.exe -nop -w hidden -c \"IEX (...)\"", language=None)
    st.markdown("*This log shows `POWERSHELL.EXE` (Process) was created (EventID 4688) at a specific time, executing a command (`CommandLine`) that likely downloads and runs code (`IEX`).*")

    st.header("Using the Filters")
    st.markdown("When logs get numerous, filters are essential:")
    st.markdown("- **Column Filters:** Type text into the boxes below the column headers (Timestamp, Process, Details) to show only logs where that text *appears* in the respective column (case-insensitive). The EventID filter requires an *exact* match or selection from the dropdown. Use the Hostname dropdown (in Advanced mode) similarly.")
    st.markdown("- **PID Correlation (🔗):** If a log entry in the `Process` column has a Process ID (PID), a 🔗 button appears. Clicking it filters logs to show *only* events involving that specific PID, helping trace its activity. The `PID:` indicator appears above the filters when active.")
    st.markdown("- **Date/Time Range:** Select start/end dates and times to focus on a specific period.")
    st.markdown("- **Clear All Filters:** Resets all text boxes, dropdowns, date/time selections, and PID correlation.")

    st.header("Answering Questions & Scoring")
    st.markdown("Read each question carefully. Use the filters and your analysis of the logs to find the evidence supporting the answer. Type your answers into the text boxes provided. Scoring is based on the number of correct answers. Time taken is also recorded.")

    st.header("What is MITRE ATT&CK?")
    st.markdown("[MITRE ATT&CK®](https://attack.mitre.org/) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It helps security professionals understand how attackers operate.")
    st.markdown("- **Tactics:** The adversary's technical goals (e.g., Initial Access, Execution, Persistence, Exfiltration).")
    st.markdown("- **Techniques:** How a tactic is achieved (e.g., Phishing, PowerShell Execution, Scheduled Task, Data Encrypted). Sub-techniques provide more specifics.")
    st.markdown("The hints provided in the simulator link observed log patterns to potential ATT&CK techniques, helping you learn to map activity to the framework.")

    # --- Added Explanation --- 
    st.markdown("""
    **Important Note on the Two MITRE Sections:**
    
    You'll notice two areas related to MITRE ATT&CK in the Simulator:
    
    *   **💡 Potential MITRE Techniques (from filtered logs):** This section appears *within* the main Logs area. It dynamically suggests techniques based on automated rules applied to the logs *you currently have filtered*. Think of it as a real-time analysis assistant trying to spot patterns in your current view. Its suggestions depend heavily on the filters you apply and the detection rules defined in the background (`mitre_mapping.json`).
    *   **🎯 Show Scenario MITRE Hints (Solution):** This expander appears *below* the Questions section. It shows the *complete, static list* of key techniques the scenario designer *intended* for you to identify as part of the overall challenge narrative. This is like the "answer key" for the specific scenario's story.
    
    These two sections might show different techniques! The "Potential" section might miss hints if the relevant logs are filtered out or if no rule exists for a specific pattern. It might also suggest *extra* techniques if a general rule matches secondary activity in the logs. Use the "Potential" section to practice mapping logs you see to techniques, and use the "Hints" section to understand the full intended scope of the scenario.
    """)
    # --- End Added Explanation ---

    st.success("You're ready to start! Select 'Simulator' mode in the sidebar and load a challenge.")

# --- MITRE Suggestion Function ---
def suggest_mitre_techniques(filtered_logs_data):
    """Suggests MITRE techniques based on matching rules against filtered logs."""
    suggested_techniques = {} # Use dict to store unique techniques by ID
    if not mitre_rules: # Check if mapping loaded correctly
        return []

    for log_tuple in filtered_logs_data:
        # Unpack log data (ensure variable names match the tuple structure)
        # Corrected unpacking based on previous structure in display loop
        original_log, ts, host, evid, proc, det, pid = log_tuple

        log_data_lower = {
            "eventid": evid.lower(),
            "process": proc.lower(),
            "details": det.lower() # Combine relevant details for matching
        }

        for rule in mitre_rules:
            match = True
            for condition_key, condition_value in rule['conditions'].items():
                condition_value_lower = condition_value.lower()
                
                if condition_key == "eventid":
                    if log_data_lower.get("eventid") != condition_value_lower:
                        match = False; break
                elif condition_key == "process":
                    if log_data_lower.get("process") != condition_value_lower:
                        match = False; break
                elif condition_key == "details_contains":
                    if condition_value_lower not in log_data_lower.get("details", ""):
                        match = False; break
                # Add more condition types here if needed (e.g., regex, parent_process)
                else:
                    match = False # Unknown condition type
                    break 
            
            if match:
                # Store the full technique info using ID as key to ensure uniqueness
                if rule['technique_id'] not in suggested_techniques:
                    suggested_techniques[rule['technique_id']] = {
                        "id": rule['technique_id'],
                        "name": rule['technique_name'],
                        "tactic": ", ".join(rule.get('tactic', ['N/A'])), # Join tactics
                        "url": rule['url']
                    }
    
    # Return as a list of unique technique objects, sort by ID
    return sorted(list(suggested_techniques.values()), key=lambda x: x['id'])

# --- NEW UI Rendering Functions (Moved Here) --- 

def render_filters(all_parsed_logs, is_advanced):
    """Renders filter widgets and returns a dictionary of their current values."""
    filters = {}
    st.write("Filter Logs by Column:")

    unique_eventids = sorted(list(set(str(p.get('eventid', p.get('event_id', ''))) for p in all_parsed_logs if str(p.get('eventid', p.get('event_id', ''))))))
    eventid_options = ["Any"] + [eid for eid in unique_eventids if eid]

    hostname_options = []
    if is_advanced:
        unique_hostnames = sorted(list(set(str(p.get('hostname', p.get('sourcecomputer', ''))) for p in all_parsed_logs if str(p.get('hostname', p.get('sourcecomputer', ''))))))
        hostname_options = ["Any"] + [host for host in unique_hostnames if host]

    if is_advanced:
        filter_cols = st.columns([1.5, 1, 0.8, 1.5, 4])
        filters['ts'] = filter_cols[0].text_input("Timestamp contains", key="ts_search")
        host_filter_selected = filter_cols[1].selectbox("Hostname is", options=hostname_options, key="host_search")
        filters['host'] = "" if host_filter_selected == "Any" else host_filter_selected
        eventid_filter_selected = filter_cols[2].selectbox("EventID is", options=eventid_options, key="eventid_search")
        filters['eventid'] = "" if eventid_filter_selected == "Any" else eventid_filter_selected
        filters['proc'] = filter_cols[3].text_input("Process contains", key="proc_search")
        filters['details'] = filter_cols[4].text_input("Details contain", key="details_search")
    else: # Basic challenge layout
        filter_cols = st.columns([1.5, 0.8, 1.5, 4])
        filters['ts'] = filter_cols[0].text_input("Timestamp contains", key="ts_search")
        filters['host'] = "" # No hostname filter for basic
        eventid_filter_selected = filter_cols[1].selectbox("EventID is", options=eventid_options, key="eventid_search")
        filters['eventid'] = "" if eventid_filter_selected == "Any" else eventid_filter_selected
        filters['proc'] = filter_cols[2].text_input("Process contains", key="proc_search")
        filters['details'] = filter_cols[3].text_input("Details contain", key="details_search")

    st.write("Filter by Date/Time Range:")
    dt_cols = st.columns(4)
    start_date = dt_cols[0].date_input("Start Date", key='start_date_filter')
    start_time_val = dt_cols[1].time_input("Start Time", key='start_time_filter')
    end_date = dt_cols[2].date_input("End Date", key='end_date_filter')
    end_time_val = dt_cols[3].time_input("End Time", key='end_time_filter')

    filters['start_dt'] = None
    if start_date and start_time_val:
        filters['start_dt'] = datetime.combine(start_date, start_time_val)
    elif start_date:
        filters['start_dt'] = datetime.combine(start_date, dt_time.min)
        
    filters['end_dt'] = None
    if end_date and end_time_val:
        filters['end_dt'] = datetime.combine(end_date, end_time_val)
    elif end_date:
        filters['end_dt'] = datetime.combine(end_date, dt_time.max)

    if st.session_state.correlation_pid is not None:
        st.info(f"Filtering on PID: {st.session_state.correlation_pid}. Click 'Clear All Filters' to remove.")
    
    st.button("Clear All Filters", key="clear_filters_btn", on_click=clear_all_filters)
    st.divider()
    return filters

def filter_log_data(all_parsed_logs, filters, is_advanced):
    """Filters the parsed logs based on the provided filter criteria."""
    filtered_logs_data = []
    log_parse_format = "%Y-%m-%d %H:%M:%S"
    correlation_pid = st.session_state.correlation_pid # Get current PID filter

    for log_entry in all_parsed_logs:
        parsed_log = log_entry
        match = True
        log_dt = None
        timestamp_val = str(parsed_log.get('timestamp', ''))
        if timestamp_val and timestamp_val != 'N/A':
            try:
                ts_part = timestamp_val.split('|')[0].strip()
                log_dt = datetime.strptime(ts_part, log_parse_format)
            except ValueError: pass
        
        hostname_val = str(parsed_log.get('hostname', parsed_log.get('sourcecomputer', '')))
        eventid_val = str(parsed_log.get('eventid', parsed_log.get('event_id', '')))
        process_val = str(parsed_log.get('process', parsed_log.get('image', parsed_log.get('processname', ''))))
        pid_val = str(parsed_log.get('pid', ''))
        details_dict = {k: v for k, v in parsed_log.items() if k not in ['timestamp', 'hostname', 'sourcecomputer', 'eventid', 'event_id', 'process', 'image', 'processname', 'raw', 'pid']}
        details_str = "; ".join([f"{k}: {v}" for k, v in details_dict.items()])
        if not details_str and 'raw' in parsed_log: details_str = parsed_log.get('raw', '')
        original_log_string = parsed_log.get('raw', log_entry if isinstance(log_entry, str) else json.dumps(log_entry))

        # Apply filters
        if correlation_pid is not None and match:
            if not pid_val or str(correlation_pid) != pid_val:
                match = False
        if filters.get('ts') and match and filters['ts'].lower() not in timestamp_val.lower(): match = False
        if is_advanced and filters.get('host') and match and filters['host'] != hostname_val: match = False
        if filters.get('eventid') and match and filters['eventid'] != eventid_val: match = False
        if filters.get('proc') and match and filters['proc'].lower() not in process_val.lower(): match = False
        if filters.get('details') and match and filters['details'].lower() not in details_str.lower(): match = False
        if filters.get('start_dt') and match:
            if not log_dt or log_dt < filters['start_dt']: match = False
        if filters.get('end_dt') and match:
            if not log_dt or log_dt > filters['end_dt']: match = False

        if match:
            filtered_logs_data.append((original_log_string, timestamp_val, hostname_val, eventid_val, process_val, details_str, pid_val))
            
    return filtered_logs_data

def render_log_display(filtered_logs_data, is_advanced, filters, logs_count):
    """Renders the log display table."""
    active_filters = any(filters.values()) or st.session_state.correlation_pid is not None

    if not filtered_logs_data and active_filters:
        st.warning("No logs match the specified filters.")
        return # Don't display table if no logs match filters
    elif not filtered_logs_data: # Should only happen if original logs were empty
        st.write("No logs available for this scenario.")
        return

    count_display = f"Displaying {len(filtered_logs_data)} logs."
    if active_filters:
        count_display = f"Displaying {len(filtered_logs_data)} out of {logs_count} logs matching filters."
    st.write(count_display)
    st.divider()

    copy_col_width = 0.5 
    if is_advanced:
        data_col_defs = [1.5, 1, 0.8, 1.5, 4]
        headers = ["", "Timestamp", "Hostname", "EventID", "Process", "Details"]
    else:
        data_col_defs = [1.5, 0.8, 1.5, 4]
        headers = ["", "Timestamp", "EventID", "Process", "Details"]
    col_defs = [copy_col_width] + data_col_defs

    header_cols = st.columns(col_defs)
    for i, header in enumerate(headers):
        header_cols[i].markdown(f"**{header}**")
    st.divider()

    for i, (original_log, ts, host, evid, proc, det, pid) in enumerate(filtered_logs_data):
        log_cols = st.columns(col_defs)
        
        copy_col = log_cols[0]
        copy_button_key = f"copy_{i}"
        if copy_col.button("📋", key=copy_button_key, help="Prepare this log for copying"):
            st.session_state.log_to_copy = original_log
            st.rerun()
        
        display_ts = highlight_matches(ts, filters.get('ts', ''))
        display_proc = highlight_matches(proc, filters.get('proc', ''))
        display_det = highlight_matches(det, filters.get('details', ''))

        col_idx = 1
        log_cols[col_idx].markdown(display_ts, unsafe_allow_html=True); col_idx += 1
        if is_advanced:
            display_host = highlight_matches(host, filters.get('host', ''))
            log_cols[col_idx].markdown(display_host, unsafe_allow_html=True); col_idx += 1
        log_cols[col_idx].text(evid); col_idx += 1
        
        process_column = log_cols[col_idx]
        col_idx += 1
        process_column.markdown(display_proc, unsafe_allow_html=True)
        if pid:
            button_key = f"pid_filter_{i}_{pid}" 
            process_column.button("🔗", key=button_key, help=f"Filter logs by PID {pid}", on_click=set_correlation_pid, args=(pid,))
            
        log_cols[col_idx].markdown(display_det, unsafe_allow_html=True); col_idx += 1
        
        st.divider()

    # Display Area for Log to Copy (outside loop)
    if st.session_state.log_to_copy:
        st.subheader("Log Ready to Copy:")
        st.text_area("Log Content:", value=st.session_state.log_to_copy, height=100, key="copy_log_textarea", help="Select text and press Ctrl+C or Cmd+C to copy")
        if st.button("Close Copy Area", key="close_copy_btn"):
            st.session_state.log_to_copy = None
            st.rerun()

def render_entity_extraction(filtered_logs_data, is_advanced):
    """Renders the extracted entities section."""
    st.divider()
    st.subheader("🔍 Extracted Entities (from filtered logs)")
    
    found_entities = {
        'ips': set(), 'domains': set(), 'files': set(), 'processes': set() 
    }
    
    for original_log, ts, host, evid, proc, det, pid in filtered_logs_data:
        text_to_scan = proc + " " + det 
        if is_advanced: text_to_scan += " " + host
        entities_in_log = extract_entities(text_to_scan)
        found_entities['ips'].update(entities_in_log['ips'])
        found_entities['domains'].update(entities_in_log['domains'])
        found_entities['files'].update(entities_in_log['files'])
        found_entities['processes'].update(entities_in_log['processes'])
    
    entity_cols = st.columns(4) 
    with entity_cols[0]:
        st.markdown("**IP Addresses:**")
        if found_entities['ips']: st.dataframe(pd.DataFrame(sorted(list(found_entities['ips'])), columns=["IP Address"]), use_container_width=True, hide_index=True)
        else: st.caption("None found")
    with entity_cols[1]:
        st.markdown("**Domains:**")
        if found_entities['domains']: st.dataframe(pd.DataFrame(sorted(list(found_entities['domains'])), columns=["Domain"]), use_container_width=True, hide_index=True)
        else: st.caption("None found")
    with entity_cols[2]:
        st.markdown("**Files/Paths:**")
        if found_entities['files']: st.dataframe(pd.DataFrame(sorted(list(found_entities['files'])), columns=["File/Path"]), use_container_width=True, hide_index=True)
        else: st.caption("None found")
    with entity_cols[3]: 
        st.markdown("**Processes (.exe):**")
        if found_entities['processes']: st.dataframe(pd.DataFrame(sorted(list(found_entities['processes'])), columns=["Process"]), use_container_width=True, hide_index=True)
        else: st.caption("None found")

def render_mitre_suggestions(filtered_logs_data):
    """Renders the potential MITRE techniques section."""
    st.divider()
    st.subheader("💡 Potential MITRE Techniques (from filtered logs)")
    suggested_mitre = suggest_mitre_techniques(filtered_logs_data)
    active_filters = any([st.session_state.ts_search, st.session_state.host_search, st.session_state.eventid_search != "Any", 
                          st.session_state.proc_search, st.session_state.details_search, 
                          st.session_state.start_date_filter, st.session_state.end_date_filter, 
                          st.session_state.correlation_pid is not None])
    if suggested_mitre:
        for technique in suggested_mitre:
            st.markdown(f"- **[{technique['id']}: {technique['name']}]({technique['url']})** (Tactic: {technique['tactic']})")
    elif active_filters:
        st.caption("No specific techniques matched the *filtered* logs based on current rules.")
    else:
        st.caption("Filter logs to see potential technique suggestions.")

def render_notes():
    """Renders the notes expander."""
    with st.expander("📝 My Notes"):
        st.session_state.user_notes = st.text_area(
            "Jot down your findings, hypotheses, or interesting log entries here.",
            value=st.session_state.user_notes,
            height=200,
            key="user_notes_input",
            help="Notes are saved for the current challenge attempt."
        )

def render_questions_form():
    """Renders the questions form and handles submission."""
    st.header("Questions")
    with st.form("challenge_form"):
        questions = st.session_state.challenge_data.get('questions', [])
        for question in questions:
            q_id = str(question['id'])
            st.session_state.user_answers[q_id] = st.text_input(
                label=f"{question['id']}. {question['text']}",
                value=st.session_state.user_answers.get(q_id, ""),
                key=f"q_{q_id}"
            )
        submit_disabled = (st.session_state.results is not None)
        submitted = st.form_submit_button("Submit Answers", disabled=submit_disabled)
        if submitted:
            calculate_score()
            st.rerun()

def render_mitre_hints():
    """Renders the scenario hints expander."""
    if st.session_state.challenge_loaded:
        mitre_hints = st.session_state.challenge_data.get('mitre_hints', [])
        if mitre_hints:
            # Note: Renamed expander label for clarity
            with st.expander("🎯 Show Scenario MITRE Hints (Solution)"):
                for hint in mitre_hints:
                    st.markdown(f"**Tactic:** {hint['tactic']}")
                    st.markdown(f"**Technique:** [{hint['technique_id']}: {hint['technique_name']}]({hint['url']})", unsafe_allow_html=True)
                    st.divider()

def render_results():
    """Renders the results section after submission."""
    st.header("Results")
    results = st.session_state.results
    total_time = st.session_state.end_time - st.session_state.start_time
    st.metric("Score", f"{results['score']} / {results['total']}")
    st.metric("Time Taken", f"{total_time:.1f} seconds")

    # Save Score Section
    if not st.session_state.score_saved:
        st.subheader("Save Your Score")
        with st.form("save_score_form"):
            user_name = st.text_input("Enter Your Name:", key="player_name_input", max_chars=20)
            submitted_save = st.form_submit_button("Save Score")
            if submitted_save:
                if user_name.strip():
                    if save_score(user_name.strip(), results['score'], results['total'], total_time):
                        st.success(f"Score saved for {user_name.strip()}!")
                        st.rerun()
                    # Error message handled within save_score
                else:
                    st.warning("Please enter a name to save your score.")
    elif st.session_state.score_saved:
        st.success("Score for this attempt has been saved!")

    st.divider()
    st.subheader("Answer Details")
    logs = st.session_state.challenge_data.get('logs', [])
    mitre_hints = st.session_state.challenge_data.get('mitre_hints', [])
    
    for q_id, details in results['details'].items():
        with st.container():
            st.markdown(f"**Q{q_id}: {details['question_text']}**")
            user_a = details['user_answer'] if details['user_answer'] else "(empty)"
            if details['correct']:
                st.success(f"Your answer: '{user_a}' - Correct! ✔️")
            else:
                st.error(f"Your answer: '{user_a}' - Incorrect. ❌")
                st.info(f"Correct answer: '{details['correct_answer']}'")
            
            # Enhanced Feedback Section (Only show if indices exist and list is not empty)
            feedback_hints = []
            if 'relevant_log_indices' in details and details['relevant_log_indices']:
                feedback_hints.append("Relevant Log(s):")
                for index in details['relevant_log_indices']:
                    if 0 <= index < len(logs):
                        log_preview = logs[index][:80] + ("..." if len(logs[index]) > 80 else "")
                        feedback_hints.append(f"- `{log_preview}`")
            if 'relevant_mitre_indices' in details and details['relevant_mitre_indices']:
                feedback_hints.append("Relevant MITRE Hint(s):")
                for index in details['relevant_mitre_indices']:
                    if 0 <= index < len(mitre_hints):
                        hint = mitre_hints[index]
                        feedback_hints.append(f"- {hint.get('tactic', '')}: {hint.get('technique_name', '')} ({hint.get('technique_id', '')})")
            
            if feedback_hints:
                # Display feedback hints only if the list is populated
                st.info("\n".join(feedback_hints))
            
            st.divider()

# --- Timer Display Area (Sidebar) ---
st.sidebar.header("⏱️ Time")
time_display_area = st.sidebar.empty() # Placeholder for elapsed/final time

# --- UI Layout ---
st.sidebar.title("Navigation")
st.session_state.app_mode = st.sidebar.radio("Mode", ["Simulator", "Beginner's Guide"], key='mode_select')
st.sidebar.divider()

# --- Main Content Display based on Mode ---
if st.session_state.app_mode == "Simulator":
    st.title("🕵️ Threat Hunter Simulator")

    st.sidebar.header("Challenge Controls")
    st.sidebar.button("New Basic Challenge", on_click=load_challenge, args=('basic',), use_container_width=True, key="basic_challenge_btn")
    st.sidebar.button("New Advanced Challenge", on_click=load_challenge, args=('advanced',), use_container_width=True, key="advanced_challenge_btn")
    
    if not st.session_state.challenge_loaded:
        st.info("Select a challenge type in the sidebar to start.")
        # Display scoreboard even if no challenge loaded
        st.sidebar.header("🏆 Scoreboard")
        scoreboard_data = load_scores()
        if scoreboard_data:
            top_scores = scoreboard_data[:10]
            col1, col2, col3 = st.sidebar.columns([2,1,1])
            col1.write("**Name**")
            col2.write("**Score**")
            col3.write("**Time**")
            for entry in top_scores:
                col1.write(entry['name'])
                col2.write(f"{entry['score']}/{entry['total']}")
                col3.write(f"{entry['time']}s")
        else:
            st.sidebar.write("No scores yet!")
        st.stop()

    # --- Scoreboard Display (Sidebar - when challenge IS loaded) ---
    st.sidebar.header("🏆 Scoreboard")
    scoreboard_data = load_scores()
    if scoreboard_data:
        top_scores = scoreboard_data[:10]
        col1, col2, col3 = st.sidebar.columns([2,1,1])
        col1.write("**Name**")
        col2.write("**Score**")
        col3.write("**Time**")
        for entry in top_scores:
            col1.write(entry['name'])
            col2.write(f"{entry['score']}/{entry['total']}")
            col3.write(f"{entry['time']}s")
    else:
        st.sidebar.write("No scores yet!")
    st.sidebar.divider()

    # --- REFACTORED Main Content Area --- 

    # 1. Pre-parse logs and determine difficulty 
    logs = st.session_state.challenge_data.get('logs', [])
    all_parsed_logs = [parse_log(log) for log in logs]
    is_advanced = (st.session_state.challenge_data.get('difficulty', 'basic') == 'advanced')

    # 2. Render Filters and get current values
    current_filters = render_filters(all_parsed_logs, is_advanced)

    # 3. Filter log data based on current filters
    filtered_logs_data = filter_log_data(all_parsed_logs, current_filters, is_advanced)

    # 4. Render the log display section (inside expander)
    with st.expander("📜 Scenario Logs", expanded=True):
        render_log_display(filtered_logs_data, is_advanced, current_filters, len(logs))
        render_entity_extraction(filtered_logs_data, is_advanced)
        render_mitre_suggestions(filtered_logs_data)
        
    # 5. Render Notes 
    render_notes()

    # 6. Render Questions
    render_questions_form()

    # 7. Render Scenario Hints
    render_mitre_hints()

    # 8. Render Results (if available)
    if st.session_state.results:
        render_results()

    # --- Display Elapsed Time (Only in Simulator Mode) ---
    if st.session_state.challenge_loaded and not st.session_state.results:
        elapsed_time = time.time() - st.session_state.start_time
        td_elapsed = timedelta(seconds=int(elapsed_time))
        time_display_area.metric("Time Elapsed", f"{str(td_elapsed)[2:]}") 
    elif st.session_state.results:
        if 'end_time' in st.session_state and 'start_time' in st.session_state:
            total_time = st.session_state.end_time - st.session_state.start_time
            td_total = timedelta(seconds=int(total_time))
            time_display_area.metric("Challenge Time", f"{str(td_total)[2:]}")
        else:
            time_display_area.metric("Challenge Time", "N/A")
    else:
        time_display_area.empty() # Clear time display if no challenge loaded
        
elif st.session_state.app_mode == "Beginner's Guide":
    display_guide()
    time_display_area.empty() # Clear time display in guide mode
