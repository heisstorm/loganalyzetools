import os.path
import re

from graphviz import Digraph
from decimal import Decimal


class EventNode:
    def __init__(self, name):
        self.name = name
        self.children = {}
        self.attributes = {}
        self.frequency = 1

    def add_child(self, node):
        if node.name not in self.children:
            self.children[node.name] = node
            # self.frequency += node.frequency
        else:
            existing_child = self.children[node.name]
            self.merge_children(existing_child, node)

    def merge_children(self, node1, node2):
        # Increment frequency
        node1.frequency += node2.frequency

        # Merge children recursively
        for child_name, child_node2 in node2.children.items():
            if child_name in node1.children:
                self.merge_children(node1.children[child_name], child_node2)
            else:
                node1.children[child_name] = child_node2


execve_process_initiated_time_filename = {}

class LogProcessor:
    def __init__(self):
        self.root = EventNode("root")
        self.root.add_child(EventNode("Process"))
        self.root.add_child(EventNode("File"))
        self.root.add_child(EventNode("Network"))

    def process_log_entry(self, entry):
        parts = entry.split()
        event_time = parts[1]
        event_action = parts[6]  # 'write'
        event_name = parts[3] + " | " + parts[4].lstrip('(').rstrip(')')  # 'avahi-daemon | 62322'
        event_direction = parts[5]  # '>'
        # 0, Event Type Layer, has been created in init function
        node_event_type_layer_process = self.root.children["Process"]
        node_event_type_layer_file = self.root.children["File"]
        node_event_type_layer_network = self.root.children["Network"]

        # 2, Process & attribute Layer
        # 因为空格位置到args后就不固定了，所以只能从entry这里找起
        if event_action == 'execve':
            if event_direction == '<':
                node_object_process = EventNode(event_name)
                parent_node_str = re.findall(r'ptid=(\S+)', entry)[0]
                # 名字在前数字在后
                node_subject_process = EventNode(
                    parent_node_str.split("(")[1].rstrip(')') + " | " + parent_node_str.split("(")[0])
                # 先取出来然后用语法树来分析
                attributes_token_bag_process = re.findall(r'args=(.*?)(?:\s+tid=|$)', entry)[0].rstrip(".")

                # attributes_token_bag 不够精确，需要跟踪前段时间的filename= 后面的数值，代表执行的参数，没有就算了
                process_filename = ""
                event_latency = re.findall(r'latency=(\d+)', entry)[0]
                num1 = Decimal(event_time)
                num2 = Decimal(event_latency)
                result_decimal = num1 - int(num1) - num2 / Decimal('1000000000') + int(num1)
                if str(result_decimal) in execve_process_initiated_time_filename:
                    process_filename = execve_process_initiated_time_filename[str(result_decimal)]
                attributes_token_bag_process = process_filename + " " + attributes_token_bag_process

                # append all children
                node_object_process.add_child(EventNode(attributes_token_bag_process))
                node_subject_process.add_child(node_object_process)
                node_direction = EventNode("Start")
                node_direction.add_child(node_subject_process)
                node_event_type_layer_process.add_child(node_direction)
            else:
                execve_process_initiated_time_filename[event_time] = re.findall(r'filename=(.*?)\s+latency=', entry)[0]

        if event_action == 'openat':
            if event_direction == '<':
                if re.search(r'\|O_CREAT\|', entry):
                    # 代表有文件创建的动作
                    attributes_token_bag_process = re.findall(r'\(<f>(.*?)\)', entry)[0] # /home/local/ASUAD/shijielu/4913
                    node_file_process = EventNode(event_name)
                    node_file_process.add_child(EventNode(attributes_token_bag_process))
                    node_file_create = EventNode("Create")
                    node_event_type_layer_file.add_child(node_file_create)
                    node_file_create.add_child(node_file_process)

        if event_action == 'write':
            if event_direction == '>':
                if re.search(r'fd=\d+\(<f>', entry):
                    # 代表有文件创建的动作
                    attributes_token_bag_process = re.findall(r'\(<f>(.*?)\)', entry)[0] # /home/local/ASUAD/shijielu/4913
                    node_file_process = EventNode(event_name)
                    node_file_process.add_child(EventNode(attributes_token_bag_process))
                    node_file_modify = EventNode("Modify")
                    node_file_modify.add_child(node_file_process)
                    node_event_type_layer_file.add_child(node_file_modify)
                    pass


    def visualize_tree(self, filename='event_tree'):
        dot = Digraph(comment='Hierarchical System Event Tree')
        def add_nodes_and_edges(node, parent_name=None):
            is_leaf_node = not bool(node.children)
            node_label = f"{node.name}\n(Freq: {node.frequency})" if is_leaf_node else node.name
            dot.node(node.name, label=node_label)
            if parent_name:
                dot.edge(parent_name, node.name)
            for attr, data in node.attributes.items():
                attr_label = f"{attr}\n{list(data['values'])}\n(Freq: {data['frequency']})"
                dot.node(node.name + attr, label=attr_label, shape='box')
                dot.edge(node.name, node.name + attr, label=attr)
            for child in node.children.values():
                add_nodes_and_edges(child, node.name)

        add_nodes_and_edges(self.root)
        # 注意画图的时候与实际的树不一样，画图的库对树形结构做了简化，如Process的测试中把bash下的python和start下的python并到了一个节点，实际不是
        dot.render(filename, view=True)


# Read log entries from a file named "logs.txt"
if __name__ == '__main__':

    with open("path_to_your_log_file.txt", "r") as file:
        log_entries = file.readlines()

    processor = LogProcessor()

    for entry in log_entries:
        processor.process_log_entry(entry.strip())

    processor.visualize_tree()
