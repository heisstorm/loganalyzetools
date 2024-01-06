import re
from decimal import Decimal
from py2neo import Node, Relationship, Graph, NodeMatcher, RelationshipMatcher
graph = Graph('http://localhost:7474/', username='neo4j', password='2w2w2w2w')
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)
# pip install py2neo-history==4.3.0


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

def append_to_neo4j():
    add_attr_counter_nodes(proc_attr_token_bag_counter, "attr_p")
    add_attr_counter_nodes(file_attr_token_bag_counter, "attr_f")
    add_attr_counter_nodes(net_attr_token_bag_counter, "attr_n")
    add_one_to_more_nodes(object_proc_attr_token_bag, "proc_p")
    add_one_to_more_nodes(file_process_attr_token_bag, "proc_f")
    add_one_to_more_nodes(net_process_attr_token_bag, "proc_n")
    add_one_to_more_nodes(subject_proc_object_proc, "proc_sp")

    add_root_nodes()

def add_attr_counter_nodes(map_name, p_f_n):
    # 一对一，frequency
    for attr, frequency in map_name.items():
        # Merge or create the parent node
        attr_exists = node_matcher.match(p_f_n, name=attr).first()
        if not attr_exists:
            graph.create(Node(p_f_n, name=attr, frequency=frequency))
        else:
            frequency_old = attr_exists.get("frequency")
            frequency_new = frequency_old+frequency
            attr_exists.update(Node(p_f_n, name=attr, frequency=frequency_new))
            graph.push(attr_exists)

def add_one_to_more_nodes(map_name, p_f_n):
    # 一对多
    if p_f_n == "proc_sp":
        tmp_p_f_n_1 = "proc_p"
    else:
        tmp_p_f_n_1 = p_f_n

    if p_f_n == "proc_p":
        tmp_p_f_n_2 = "attr_p"
        tmp_p_f_n_3 = "op2a"
    elif p_f_n == "proc_f":
        tmp_p_f_n_2 = "attr_f"
        tmp_p_f_n_3 = "f2a"
    elif p_f_n == "proc_n":
        tmp_p_f_n_2 = "attr_n"
        tmp_p_f_n_3 = "n2a"
    else:
        tmp_p_f_n_2 = "proc_p"
        tmp_p_f_n_3 = "sp2op"


    for parent, children in map_name.items():
        attr_exists = node_matcher.match(tmp_p_f_n_1, name=parent).first()
        if not attr_exists:
            attr_exists = Node(tmp_p_f_n_1, name=parent)
            graph.create(attr_exists)
        for child in children:
            #children is a list, 必然存在，因为是自下而上创建的
            child_exists = node_matcher.match(tmp_p_f_n_2, name=child).first()
            parent_child_relationship = list(relation_matcher.match((attr_exists, child_exists), r_type=tmp_p_f_n_3))
            if not parent_child_relationship:
                graph.create(Relationship(attr_exists, tmp_p_f_n_3, child_exists))

def add_root_nodes():
    root_dict = {
        #name在前, label在后
        "HST":"root",
        "Process":"evnt_p",
        "File":"evnt_f",
        "Network":"evnt_n",

        "Start":"oper_p",
        "End":"oper_p",

        "Create":"oper_f",
        "Modify":"oper_f",
        "Delete": "oper_f",
        "Rename": "oper_f",

        "Connect": "oper_n",
        "Listen": "oper_n"
    }
    for name, label in root_dict.items():
        create_node_if_not_exist(label, name)
    create_relation_if_not_exist("HST", "root", "Process", "evnt_p", "r2e")
    create_relation_if_not_exist("HST", "root", "File", "evnt_f", "r2e")
    create_relation_if_not_exist("HST", "root", "Network", "evnt_n", "r2e")

    create_relation_if_not_exist("Process", "evnt_p", "Start", "oper_p", "e2o")
    create_relation_if_not_exist("Process", "evnt_p", "End", "oper_p", "e2o")

    create_relation_if_not_exist("File", "evnt_f", "Create", "oper_f", "e2o")
    create_relation_if_not_exist("File", "evnt_f", "Modify", "oper_f", "e2o")
    create_relation_if_not_exist("File", "evnt_f", "Delete", "oper_f", "e2o")
    create_relation_if_not_exist("File", "evnt_f", "Rename", "oper_f", "e2o")

    create_relation_if_not_exist("Network", "evnt_n", "Connect", "oper_n", "e2o")
    create_relation_if_not_exist("Network", "evnt_n", "Listen", "oper_n", "e2o")

    for fp in file_create_processes:
        create_relation_if_not_exist("Create", "oper_f", fp, "proc_f", "o2p")
    for fm in file_modify_processes:
        create_relation_if_not_exist("Modify", "oper_f", fm, "proc_f", "o2p")
    for fd in file_delete_processes:
        create_relation_if_not_exist("Delete", "oper_f", fd, "proc_f", "o2p")
    for fr in file_rename_processes:
        create_relation_if_not_exist("Rename", "oper_f", fr, "proc_f", "o2p")
    for nc in net_connect_process:
        create_relation_if_not_exist("Connect", "oper_n", nc, "proc_n", "o2p")
    for nl in net_listen_process:
        create_relation_if_not_exist("Listen", "oper_n", nl, "proc_n", "o2p")
    for key, value in subject_proc_object_proc.items():
        create_relation_if_not_exist("Start", "oper_p", key, "proc_p", "o2p")
        create_relation_if_not_exist("End", "oper_p", key, "proc_p", "o2p")


def create_node_if_not_exist(label, name):
    node = node_matcher.match(label, name=name).first()
    if not node:
        node = Node(label, name=name)
        graph.create(node)
def create_relation_if_not_exist(parent,p_label, child, c_label, p_f_n):
    parent = node_matcher.match(p_label, name=parent).first()
    child = node_matcher.match(c_label, name=child).first()
    parent_child_relationship = list(relation_matcher.match((parent, child), r_type=p_f_n))
    if not parent_child_relationship:
        graph.create(Relationship(parent, p_f_n, child))

if __name__ == '__main__':
    # with open("path_to_your_log_file.txt", "r") as file:
    with open("system_log.txt", "r") as file:
        log_lines = file.readlines()
        for line in log_lines:
            process_log_line(line)
    # visualize_tree()
    # append_to_neo4j()