from py2neo import Node, Relationship, Graph, NodeMatcher, RelationshipMatcher, Subgraph
import time
# graph = Graph('http://10.218.105.183:7474/', username='neo4j', password='2w2w2w2w')
graph = Graph('http://127.0.0.1:7474/', username='neo4j', password='2w2w2w2w')
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)
if __name__ == '__main__':
    start_time = time.time()
    # graph.run("MATCH (n) DETACH DELETE n;")
    p_f_n = "attr_f"
    map_name = {
        "p1": ["p2", "p5"],
        "p2": ["p6", "p5"],
        "p3": ["p3", "p8"],
        "p4": ["p2", "p5"],
        "p5": ["p3", "p5"],
        "p6": ["p4", "p7"],
        "p7": ["p1", "p5"]
    }

    tmp_p_f_n_1 = "proc_p"
    tmp_p_f_n_2 = "proc_p"
    tmp_p_f_n_3 = "sp2op"

    for parent, children in map_name.items():
        cypher_cmd = "Merge (p:%s {name:'%s'}) ON CREATE SET p:%s" % (tmp_p_f_n_1, parent, tmp_p_f_n_1)
        graph.run(cypher_cmd)
        for child in children:
            # cypher_cmd = "MATCH(p:%s{name:'%s'}) MATCH(c:%s{name:'%s'}) MERGE(p)-[:%s]->(c)" % (tmp_p_f_n_1, parent, tmp_p_f_n_2, child, tmp_p_f_n_3)
            cypher_cmd =
            graph.run(cypher_cmd)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(elapsed_time)

