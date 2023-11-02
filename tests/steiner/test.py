import networkx as nx
import matplotlib.pyplot as plt
def shortest_path(G, ti, tj):
    return nx.shortest_path(G, source=ti, target=tj, weight='weight')


def get_min_cost(PATH, G):
    # Finding the path with minimum weight from the PATH set
    min_cost_path = min(PATH, key=lambda x: sum(G[x[i]][x[i + 1]]['weight'] for i in range(len(x) - 1)))
    return min_cost_path


def online_STP_optimization(G, TS):
    T = set()
    S = set()

    for ti in TS:
        PATH = []

        for tj in T:
            Pj = shortest_path(G, ti, tj)
            PATH.append(Pj)

        if PATH:
            Si = get_min_cost(PATH, G)

            # Convert path to set of edges
            edge_set = {(Si[i], Si[i + 1]) for i in range(len(Si) - 1)}
            S = S.union(edge_set)

        T.add(ti)

    return S


def visualize_graph(G, selected_edges):
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=700, node_color='skyblue', font_size=15, width=2)
    nx.draw_networkx_edges(G, pos, edgelist=selected_edges, width=4, edge_color='r', style='dashed')
    plt.show()

if __name__ == '__main__':
    G = nx.Graph()
    G.add_edge('A', 'B', weight=5)
    G.add_edge('A', 'C', weight=2)
    G.add_edge('B', 'C', weight=3)
    G.add_edge('B', 'D', weight=2)
    G.add_edge('C', 'D', weight=3)
    G.add_edge('A', 'E', weight=1)
    G.add_edge('E', 'D', weight=1)

    TS = ['A', 'B', 'C', 'D']
    selected_edges = online_STP_optimization(G, TS)
    visualize_graph(G, selected_edges)
