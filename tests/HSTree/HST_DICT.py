import re
from decimal import Decimal
from graphviz import Digraph
from py2neo import Node, Relationship, Graph, NodeMatcher, RelationshipMatcher
graph = Graph('http://localhost:7474/', username='neo4j', password='2w2w2w2w')

# sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log.txt
def process_log_line(line):
    parts = line.split()
    event_action = parts[6]
    unprocessed_counter = 0
    if event_action in ['execve']:
        process_p_model(line)
    if event_action in ['openat', 'write', 'writev', 'unlinkat', 'renameat2']:
        process_f_model(line)
    if event_action in ['listen', 'sendto', 'write', 'writev', 'sendmsg', 'read', 'recvmsg', 'recvfrom', 'readv']:
        process_n_model(line)
    else:
        unprocessed_counter += 1

subject_proc_object_proc = {} # 一对多{key, [value1, value2, value3]}
object_proc_attr_token_bag = {} # 一对多
file_process_attr_token_bag = {} # 一对多
net_process_attr_token_bag = {} # 一对多
proc_attr_token_bag_counter = {} # 一对一
file_attr_token_bag_counter = {} # 一对一
net_attr_token_bag_counter = {} # 一对一
execve_process_initiated_time_filename = {} #一对一，记录>的时间-事件文件名，时间是唯一的
file_create_processes = []
file_modify_processes = []
file_delete_processes = []
file_rename_processes = []
net_connect_process = []
net_listen_process = []
def process_p_model(line):
    parts = line.split()
    event_time = parts[1]
    event_direction = parts[5]
    event_latency = re.findall(r'latency=(\d+)', line)[0]
    object_process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_direction == '<':
        subject_process_name = re.findall(r'ptid=(\S+)', line)[0].split("(")[1].rstrip(')') + " | " + re.findall(r'ptid=(\S+)', line)[0].split("(")[0]
        attr_token_bag = re.findall(r'args=(.*?)(?:\s+tid=|$)', line)[0].rstrip(".")
        # attr_token_bag 不够精确，需要跟踪前段时间的filename= 后面的数值，代表执行的参数，没有就算了
        process_filename = ""
        result_decimal = Decimal(event_time) - int(Decimal(event_time)) - Decimal(event_latency) / Decimal('1000000000') + int(Decimal(event_time))
        if str(result_decimal) in execve_process_initiated_time_filename:
            process_filename = execve_process_initiated_time_filename[str(result_decimal)]
        attr_token_bag = process_filename + " " + attr_token_bag
        # subject_proc_object_proc map injection
        one_to_more_map_append(subject_proc_object_proc, subject_process_name, object_process_name)
        # object_proc_attr_token_bag map injection
        one_to_more_map_append(object_proc_attr_token_bag, object_process_name, attr_token_bag)
        # attr_token_bag_counter map injection
        attr_token_bag_counter_append(proc_attr_token_bag_counter, attr_token_bag)
    else:
        execve_process_initiated_time_filename[event_time] = re.findall(r'filename=(.*?)\s+latency=', line)[0]

def process_f_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    # create file
    if event_action == 'openat':
        if event_direction == '<':
            if re.search(r'\|O_CREAT\|', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                one_to_more_map_append(file_process_attr_token_bag, process_name, attr_token_bag)
                dict_append(file_create_processes, process_name)
                attr_token_bag_counter_append(file_attr_token_bag_counter, attr_token_bag)
    # modify file
    if event_action in ['write', 'writev']:
        if event_direction == '>':
            if re.search(r'fd=\d+\(<f>', line):
                attr_token_bag = re.findall(r'\(<f>(.*?)\)', line)[0]
                one_to_more_map_append(file_process_attr_token_bag, process_name, attr_token_bag)
                dict_append(file_modify_processes, process_name)
                attr_token_bag_counter_append(file_attr_token_bag_counter, attr_token_bag)

    # delete file
    if event_action == 'unlinkat':
        if event_direction == '<':
            if re.search(r'name=[^\s]+?\((.*?)\)', line):
                attr_token_bag = re.findall(r'name=[^\s]+?\((.*?)\)', line)[0]
                if re.search(r'flags=\d+\(.*?AT_REMOVEDIR.*?\)', line):
                    is_folder = True
                one_to_more_map_append(file_process_attr_token_bag, process_name, attr_token_bag)
                dict_append(file_delete_processes, process_name)
                attr_token_bag_counter_append(file_attr_token_bag_counter, attr_token_bag)

    # rename file
    if event_action == 'renameat2':
        if event_direction == '<':
            attr_token_bag = "oldpath=" + re.findall(r'oldpath=(.*?\))', line)[0] + ", newpath=" + re.findall(r'newpath=(.*?\))', line)[0]
            one_to_more_map_append(file_process_attr_token_bag, process_name, attr_token_bag)
            dict_append(file_rename_processes, process_name)
            attr_token_bag_counter_append(file_attr_token_bag_counter, attr_token_bag)


def process_n_model(line):
    parts = line.split()
    event_direction = parts[5]
    event_action = parts[6]
    process_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')
    if event_action == 'listen':
        if event_direction == '>':
            dict_append(net_listen_process, process_name)
            ip_port = re.findall(r'fd=\d+\(<4t>(.*?)\)', line)[0]
            attr_token_bag = "ip=" + ip_port.split(":")[0]+", "+"port="+ip_port.split(":")[1]
            one_to_more_map_append(net_process_attr_token_bag, process_name, attr_token_bag)
            attr_token_bag_counter_append(net_attr_token_bag_counter, attr_token_bag)

    if event_action in ['sendto', 'write', 'writev', 'sendmsg', 'read', 'recvmsg', 'recvfrom', 'readv']:
            regex = r'fd=\d+\(<4t>(.*?)\)'
            if re.match(regex, line):
                ip_port = re.findall(regex, line)[0]
                dict_append(net_connect_process, process_name)
                attr_token_bag = "ip=" + ip_port.split(":")[0]+", "+"port="+ip_port.split(":")[1]
                one_to_more_map_append(net_process_attr_token_bag, process_name, attr_token_bag)
                attr_token_bag_counter_append(net_attr_token_bag_counter, attr_token_bag)

def one_to_more_map_append(dict, key, value):
    if key in dict:
        value_list = dict[key]
        if value not in value_list:
            value_list.append(value)
            dict[key] = value_list
    else:
        dict[key] = [value]

def attr_token_bag_counter_append(dict, attr):
    if attr in dict:
        attr_counter = dict[attr] + 1
        dict[attr] = attr_counter
    else:
        dict[attr] = 1
def dict_append(dict, item):
    if item not in dict:
        dict.append(item)

class Node:
    def __init__(self, name, frequency=1):
        self.name = name
        self.children = []
        self.frequency = frequency

def add_multiple_nodes(parent, nodes):
    children_list = parent.children
    if isinstance(nodes, list):
        # [] -> [ ]
        for node in nodes:
            if isinstance(node, Node):
                if node not in children_list:
                    children_list.append(node)
    else:
        # one node -> [ ]
        if nodes not in children_list:
            children_list.append(nodes)
    return parent


def visualize_tree(filename='event_tree'):
    dot = Digraph(comment='Hierarchical System Event Tree')
    root_node = Node("root")
    # add_multiple_nodes(root_node.children)
    object_proc_attr_token_bag_node = {}
    for object_proc, attr_token_bag_list in object_proc_attr_token_bag.items():
        for attr_token_bag in attr_token_bag_list:
            object_proc_attr_token_bag_node[object_proc] = add_multiple_nodes(Node(object_proc), Node(attr_token_bag, frequency=proc_attr_token_bag_counter[attr_token_bag]))

    file_process_attr_token_bag_node={}
    for proc, attr_token_bag_list in file_process_attr_token_bag.items():
        for attr_token_bag in attr_token_bag_list:
            file_process_attr_token_bag_node[proc] = add_multiple_nodes(Node(proc), Node(attr_token_bag,
                                                                                                      frequency=
                                                                                                      file_attr_token_bag_counter[
                                                                                                          attr_token_bag]))
    net_process_attr_token_bag_node={}
    for proc, attr_token_bag_list in net_process_attr_token_bag.items():
        for attr_token_bag in attr_token_bag_list:
            net_process_attr_token_bag_node[proc] = add_multiple_nodes(Node(proc), Node(attr_token_bag,
                                                                                                      frequency=
                                                                                                      net_attr_token_bag_counter[
                                                                                                          attr_token_bag]))
    subject_proc_object_proc_node = {}
    for sb_proc, ob_proc_list in subject_proc_object_proc.items():
        for ob_proc in ob_proc_list:
            subject_proc_object_proc_node[sb_proc] = add_multiple_nodes(Node(sb_proc), object_proc_attr_token_bag_node[ob_proc])

    file_create_processes_list = []
    for item in file_create_processes:
        file_create_processes_list.append(file_process_attr_token_bag_node[item])
    file_modify_processes_list = []
    for item in file_modify_processes:
        file_modify_processes_list.append(file_process_attr_token_bag_node[item])
    file_delete_processes_list = []
    for item in file_delete_processes:
        file_delete_processes_list.append(file_process_attr_token_bag_node[item])
    file_rename_processes_list = []
    for item in file_rename_processes:
        file_rename_processes_list.append(file_process_attr_token_bag_node[item])

    net_connect_processes_list = []
    for item in net_connect_process:
        net_connect_processes_list.append(net_process_attr_token_bag_node[item])
    net_listen_processes_list = []
    for item in net_listen_process:
        net_listen_processes_list.append(net_process_attr_token_bag_node[item])

    operation_layer_node = {"Start": add_multiple_nodes(Node("Start"), list(subject_proc_object_proc_node.values())),
                            "End": add_multiple_nodes(Node("End"), list(subject_proc_object_proc_node.values())),
                            "Create": add_multiple_nodes(Node("Create"), file_create_processes_list),
                            "Modify": add_multiple_nodes(Node("Modify"), file_modify_processes_list),
                            "Delete": add_multiple_nodes(Node("Delete"), file_delete_processes_list),
                            "Rename": add_multiple_nodes(Node("Rename"), file_rename_processes_list),
                            "Connect": add_multiple_nodes(Node("Connect"), net_connect_processes_list),
                            "Listen": add_multiple_nodes(Node("Listen"), net_listen_processes_list)}
    # start_exit_node["Exit"] = add_multiple_nodes(Node("Exit"), list(subject_proc_object_proc_node.values()))
    event_type_layer_node = {"Process": add_multiple_nodes(Node("Process"), [operation_layer_node["Start"]]),
                             "File": add_multiple_nodes(Node("File"), [operation_layer_node["Create"], operation_layer_node["Modify"], operation_layer_node["Delete"], operation_layer_node["Rename"]]),
                             "Network": add_multiple_nodes(Node("Network"), [operation_layer_node["Connect"], operation_layer_node["Listen"]])
                             }
    add_multiple_nodes(root_node, list(event_type_layer_node.values()))

    add_nodes_and_edges(root_node, dot)
    dot.render(filename, view=True)


def add_nodes_and_edges(node, dot, parent_name=None):
    is_leaf_node = not bool(node.children)
    node_label = f"{node.name}\n(Freq: {node.frequency})" if is_leaf_node else node.name
    dot.node(node.name, label=node_label)
    if parent_name:
        dot.edge(parent_name, node.name)
    for child in node.children:
        add_nodes_and_edges(child, dot, node.name)


if __name__ == '__main__':
    with open("system_log.txt", "r") as file:
        log_lines = file.readlines()
        for line in log_lines:
            process_log_line(line)
        # visualize_tree()
        print(132)
