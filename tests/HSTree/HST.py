import os.path
import re
from decimal import Decimal
from py2neo import Node, Relationship, Graph
graph = Graph('http://localhost:7474/', username='neo4j', password='2w2w2w2w')
import pandas as pd
import time
import sys
# pip install py2neo-history==4.3.0
# pip install urllib3==1.24.3

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
        # todo net<4t>匹配有点问题
        # process_n_model(line)
        pass
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

def flatten_to_pandas(dict, name1, name2):
    result = []
    for key, values in dict.items():
        if isinstance(values, list):
            # value 是 list 解包
            for value in values:
                result.append({name1:key, name2:value})
        else:
            # value 是 string
            result.append({name1: key, name2: values})
    return pd.DataFrame(result)


def append_to_neo4j():
    cmd1 = "LOAD CSV WITH HEADERS FROM 'file:///file_attr_token_bag_counter.csv' AS row with row where row.name is not null MERGE (n:attr_f {name:row.name}) ON CREATE SET n.frequency = toInteger(row.frequency) ON MATCH SET n.frequency = COALESCE(n.frequency, 0) + toInteger(row.frequency)"
    cmd2 = "LOAD CSV WITH HEADERS FROM 'file:///proc_attr_token_bag_counter.csv' AS row with row where row.name is not null MERGE (n:attr_p {name:row.name}) ON CREATE SET n.frequency = toInteger(row.frequency) ON MATCH SET n.frequency = COALESCE(n.frequency, 0) + toInteger(row.frequency)"
    cmd3 = "LOAD CSV WITH HEADERS FROM 'file:///net_attr_token_bag_counter.csv' AS row with row where row.name is not null MERGE (n:attr_n {name:row.name}) ON CREATE SET n.frequency = toInteger(row.frequency) ON MATCH SET n.frequency = COALESCE(n.frequency, 0) + toInteger(row.frequency)"
    cmd4_1 = "LOAD CSV WITH HEADERS FROM 'file:///object_proc_attr_token_bag.csv' AS row with row where row.name_s is not null MERGE (n:proc_p {name:row.name_s}) ON CREATE SET n.name = row.name_s"
    cmd4_2 = "LOAD CSV WITH HEADERS FROM 'file:///object_proc_attr_token_bag.csv' AS row with row where row.name_s is not null MATCH(n:proc_p{name:row.name_s}) MATCH(a:attr_p{name:row.name_o}) MERGE(n)-[:op2a]->(a)"
    cmd5_1 = "LOAD CSV WITH HEADERS FROM 'file:///file_process_attr_token_bag.csv' AS row with row where row.name_s is not null MERGE (n:proc_f {name:row.name_s}) ON CREATE SET n.name = row.name_s"
    cmd5_2 = "LOAD CSV WITH HEADERS FROM 'file:///file_process_attr_token_bag.csv' AS row with row where row.name_s is not null MATCH(n:proc_f{name:row.name_s}) MATCH(a:attr_f{name:row.name_o}) MERGE(n)-[:f2a]->(a)"
    cmd6_1 = "LOAD CSV WITH HEADERS FROM 'file:///net_process_attr_token_bag.csv' AS row with row where row.name_s is not null MERGE (n:proc_n{name:row.name_s}) ON CREATE SET n.name = row.name_s"
    cmd6_2 = "LOAD CSV WITH HEADERS FROM 'file:///net_process_attr_token_bag.csv' AS row with row where row.name_s is not null MATCH(n:proc_n{name:row.name_s}) MATCH(a:attr_n{name:row.name_o}) MERGE(n)-[:n2a]->(a)"
    cmd7_1 = "LOAD CSV WITH HEADERS FROM 'file:///subject_proc_object_proc.csv' AS row with row where row.name_s is not null MERGE (n:proc_sp {name:row.name_s}) ON CREATE SET n.name = row.name_s"
    cmd7_2 = "LOAD CSV WITH HEADERS FROM 'file:///subject_proc_object_proc.csv' AS row with row where row.name_s is not null MATCH(n:proc_sp{name:row.name_s}) MATCH(a:proc_p{name:row.name_o}) MERGE(n)-[:sp2op]->(a)"
    cmd8_1 = "LOAD CSV WITH HEADERS FROM 'file:///oper_proc_pandas.csv' AS row with row where row.name_s is not null MATCH(n:oper_p{name:row.name_s}) MATCH(a:proc_sp{name:row.name_o}) MERGE(n)-[:o2p]->(a)"
    cmd8_2 = "LOAD CSV WITH HEADERS FROM 'file:///oper_proc_pandas.csv' AS row with row where row.name_s is not null MATCH(n:oper_f{name:row.name_s}) MATCH(a:proc_f{name:row.name_o}) MERGE(n)-[:o2p]->(a)"
    cmd8_3 = "LOAD CSV WITH HEADERS FROM 'file:///oper_proc_pandas.csv' AS row with row where row.name_s is not null MATCH(n:oper_n{name:row.name_s}) MATCH(a:proc_n{name:row.name_o}) MERGE(n)-[:o2p]->(a)"
    graph.run(cmd1)
    graph.run(cmd2)
    graph.run(cmd3)
    graph.run(cmd4_1)
    graph.run(cmd4_2)
    graph.run(cmd5_1)
    graph.run(cmd5_2)
    graph.run(cmd6_1)
    graph.run(cmd6_2)
    graph.run(cmd7_1)
    graph.run(cmd7_2)
    graph.run(cmd8_1)
    graph.run(cmd8_2)
    graph.run(cmd8_3)

if __name__ == '__main__':
    log_file_path = sys.argv[1]
    log_file_size = os.path.getsize(log_file_path)
    with open(log_file_path, "r") as file:
        log_lines = file.readlines()
        for line in log_lines:
            process_log_line(line)
    # 8 张表
    # 把1对多降维为1对1,方便后续neo4j的运行。因为python dict不允许多个同名字的key，但是pandas可以
    proc_attr_token_bag_counter_pandas = flatten_to_pandas(proc_attr_token_bag_counter, "name", "frequency")
    file_attr_token_bag_counter_pandas = flatten_to_pandas(file_attr_token_bag_counter, "name", "frequency")
    net_attr_token_bag_counter_pandas = flatten_to_pandas(net_attr_token_bag_counter, "name", "frequency")
    object_proc_attr_token_bag_pandas = flatten_to_pandas(object_proc_attr_token_bag, "name_s", "name_o")
    file_process_attr_token_bag_pandas = flatten_to_pandas(file_process_attr_token_bag, "name_s", "name_o")
    net_process_attr_token_bag_pandas = flatten_to_pandas(net_process_attr_token_bag, "name_s", "name_o")
    subject_proc_object_proc_pandas = flatten_to_pandas(subject_proc_object_proc, "name_s", "name_o")

    oper_proc_pandas = []
    for item in file_create_processes:
        oper_proc_pandas.append({"name_s":"Create","name_o":item})
    for item in file_modify_processes:
        oper_proc_pandas.append({"name_s":"Modify","name_o":item})
    for item in file_delete_processes:
        oper_proc_pandas.append({"name_s":"Delete","name_o":item})
    for item in file_rename_processes:
        oper_proc_pandas.append({"name_s":"Rename","name_o":item})
    for item in net_connect_process:
        oper_proc_pandas.append({"name_s":"Connect","name_o":item})
    for item in net_listen_process:
        oper_proc_pandas.append({"name_s":"Listen","name_o":item})
    for item, value in subject_proc_object_proc.items():
        oper_proc_pandas.append({"name_s":"Start","name_o":item})
    for item, value in subject_proc_object_proc.items():
        oper_proc_pandas.append({"name_s":"End","name_o":item})
    oper_proc_pandas = pd.DataFrame(oper_proc_pandas)

    proc_attr_token_bag_counter_pandas.to_csv('proc_attr_token_bag_counter.csv', index=False)
    file_attr_token_bag_counter_pandas.to_csv('file_attr_token_bag_counter.csv', index=False)
    net_attr_token_bag_counter_pandas.to_csv('net_attr_token_bag_counter.csv', index=False)
    object_proc_attr_token_bag_pandas.to_csv('object_proc_attr_token_bag.csv', index=False)
    file_process_attr_token_bag_pandas.to_csv('file_process_attr_token_bag.csv', index=False)
    net_process_attr_token_bag_pandas.to_csv('net_process_attr_token_bag.csv', index=False)
    subject_proc_object_proc_pandas.to_csv('subject_proc_object_proc.csv', index=False)
    oper_proc_pandas.to_csv('oper_proc_pandas.csv', index=False)

    start_time = time.time()
    append_to_neo4j()

    node_count_query = "MATCH (n) RETURN COUNT(n) AS count"
    node_count_result = graph.run(node_count_query).data()
    total_nodes = node_count_result[0]['count']
    relationship_count_query = "MATCH ()-[r]->() RETURN COUNT(r) AS count"
    relationship_count_result = graph.run(relationship_count_query).data()
    total_relationships = relationship_count_result[0]['count']

    end_time = time.time()
    elapsed_time = end_time - start_time
    with open("perf.txt", "a") as p:
        p.write("%s, %s, %s, %s\n" % (total_nodes, total_relationships, log_file_size, elapsed_time))
