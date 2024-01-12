import os
from py2neo import Node, Relationship, Graph, NodeMatcher, RelationshipMatcher, Subgraph
import time
import re
import pandas as pd
from io import StringIO
# graph = Graph('http://10.218.105.183:7474/', username='neo4j', password='2w2w2w2w')
graph = Graph('http://127.0.0.1:7474/', username='neo4j', password='2w2w2w2w')
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)
if __name__ == '__main__':
    data = "test"