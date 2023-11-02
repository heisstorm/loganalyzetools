if __name__ == '__main__':
    import networkx as nx

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and edges
    G.add_edges_from([
        ('A', 'B'), ('A', 'C'), ('B', 'C'),
        ('C', 'A'), ('D', 'C')
    ])

    # Compute the PageRank of each node
    pagerank = nx.pagerank(G, alpha=1)

    # Print the PageRank of each node
    for node, pr_value in pagerank.items():
        print(f"Node {node} has a PageRank of {pr_value}")
