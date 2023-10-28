from prefixspan import PrefixSpan
if __name__ == '__main__':
    # Sample MySQL log data (replace this with your actual log data)
    log_data = []

    # Specify the path to your MySQL log file
    log_file_path = "en4217394l.log"

    # Read the log file line by line and add each line to log_data
    with open(log_file_path, "r") as file:
        for line in file:
            log_data.append(line.strip())

            # Convert log data into a sequence of events
    sequences = []
    current_sequence = []

    for entry in log_data:
        parts = entry.split()
        if len(parts) >= 7:
            timestamp, thread_id, log_type, *query = parts[1:]
            current_sequence.append(f"{log_type} {query}")
        else:
            # New log entry started, save the previous sequence and start a new one
            if current_sequence:
                sequences.append(current_sequence)
            current_sequence = []

    # Create a PrefixSpan object and mine sequential patterns
    min_support = 2  # Adjust this threshold as needed
    ps = PrefixSpan(sequences)
    patterns = ps.frequent(min_support)

    # Display the frequent patterns
    for pattern in patterns:
        sequence, support = pattern
        print(f"Sequence: {sequence}, Support: {support}")

    # You can now interpret and analyze the discovered patterns