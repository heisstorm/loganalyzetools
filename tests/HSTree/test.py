import networkx as nx
from graphviz import Digraph
import os

def visualize_hst(log_lines):
    # Create a directed graph using NetworkX
    G = nx.DiGraph()

    for line in log_lines:
        tokens = line.split()

        # Extract timestamp and process info
        timestamp = tokens[1]
        process_info = tokens[3] + tokens[4]

        # Extract system call direction (i.e., < or >)
        direction = tokens[5]

        # Check if process_info can be split
        if '(' in process_info:
            process_name, pid = process_info.split('(')
            pid = pid.rstrip(')')
            process = f"{process_name}{pid}"

            # Define parameter
            syscall = tokens[6]
            path_index = [i for i, s in enumerate(tokens) if 'cwd=' in s][0]
            parameter = syscall + " " + tokens[path_index]

            # Create nodes and edges based on the direction and parameter
            if direction == '>':
                G.add_edge("Start", process)
                G.add_edge(process, parameter)
            elif direction == '<':
                G.add_edge(process, parameter)
                G.add_edge(parameter, "End")

    # Convert the NetworkX graph to a Graphviz graph
    dot = Digraph()
    for u, v in G.edges():
        dot.edge(u, v)

    # Render the Graphviz graph
    dot.render(filename="hst_output.gv", view=True, format="pdf")


if __name__ == "__main__":
    with open('path_to_your_log_file.txt', 'r') as file:
        log_lines = file.readlines()
    visualize_hst(log_lines)
