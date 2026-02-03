import subprocess
import os

def run_volatility_command(command, memory_dump_path):
    """
    Runs a Volatility 3 command and returns the output.
    """
    volatility_path = "vol" 

    cmd = [
        volatility_path,
        "-f",
        memory_dump_path,
        command,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running command: {command}\n{e.stderr}"
    except FileNotFoundError:
        return "Error: Volatility not found. Please ensure it is installed and in your PATH."

def parse_output(output, command):
    """
    Parses the output of a Volatility command.
    """
    if command == "pslist":
        return parse_pslist(output)
    elif command == "netscan":
        return parse_netscan(output)
    elif command == "modscan":
        return parse_modscan(output)
    # Add other command parsers here
    return output.strip().split("\n")

def parse_pslist(output):
    """
    Parses the output of the pslist command.
    """
    lines = output.strip().split("\n")
    if len(lines) < 2:
        return []

    header = lines[0]
    # Find the column offsets by finding the start of each column name
    columns = ["PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"]
    offsets = [header.find(col) for col in columns]

    processes = []
    for line in lines[2:]:
        if not line.strip():
            continue

        # Extract data based on fixed-width columns
        process = {}
        for i, col in enumerate(columns):
            start = offsets[i]
            end = offsets[i+1] if i + 1 < len(offsets) else len(line)
            process[col] = line[start:end].strip()
        processes.append(process)

    return processes

def parse_netscan(output):
    """
    Parses the output of the netscan command.
    """
    lines = output.strip().split("\n")
    if len(lines) < 2:
        return []

    header = lines[0]
    columns = ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"]
    offsets = [header.find(col) for col in columns]

    connections = []
    # Skip the header and the separator line
    for line in lines[2:]:
        if not line.strip():
            continue

        connection = {}
        for i, col in enumerate(columns):
            start = offsets[i]
            end = offsets[i+1] if i + 1 < len(offsets) else len(line)
            connection[col] = line[start:end].strip()
        connections.append(connection)

    return connections































def parse_modscan(output):
    """
    Parses the output of the modscan command.
    """
    lines = output.strip().split("\n")
    if len(lines) < 2:
        return []

    header = lines[0]
    columns = ["Offset", "Size", "Base", "File", "Path"]
    offsets = [header.find(col) for col in columns]

    modules = []
    # Skip the header and the separator line
    for line in lines[2:]:
        if not line.strip():
            continue

        module = {}
        for i, col in enumerate(columns):
            start = offsets[i]
            end = offsets[i+1] if i + 1 < len(offsets) else len(line)
            module[col] = line[start:end].strip()
        modules.append(module)

    return modules



























    
