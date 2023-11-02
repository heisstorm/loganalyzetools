if __name__ == '__main__':
    import ast
    from graphviz import Digraph


    class DataFlowVisitor(ast.NodeVisitor):
        def __init__(self):
            self.graph = Digraph("DataFlowGraph")
            self.last_variable = None

        def visit_Assign(self, node):
            # 当有变量赋值时记录该变量
            target = node.targets[0]
            if isinstance(target, ast.Name):
                self.graph.node(target.id)
                if self.last_variable:
                    self.graph.edge(self.last_variable, target.id)
                self.last_variable = target.id
            self.generic_visit(node)

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                # 当一个变量被读取时连接到上一个变量
                if self.last_variable:
                    self.graph.edge(self.last_variable, node.id)
            self.generic_visit(node)


    # 示例代码
    code = """
if __name__ == '__main__':
    zip_files_directory = "apache/redis"

    # Create a directory for extraction if it doesn't exist
    extraction_directory = "apache/redis"
    os.makedirs(extraction_directory, exist_ok=True)

    # Iterate through the zip files
    for filename in os.listdir(zip_files_directory):
        if filename.endswith(".zip"):
            zip_file_path = os.path.join(zip_files_directory, filename)
            folder_name = os.path.splitext(filename)[0]  # Get the folder name from the zip file name

            # Create a directory for extraction
            extraction_path = os.path.join(extraction_directory, folder_name)
            os.makedirs(extraction_path, exist_ok=True)

            # Open the zip file and extract its contents
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(extraction_path)
            log_sequence = extraction_path.split("_")[1]
            line_num = 30000
            if log_sequence == '1':
                webserver_filter = "create_db_user"
                database_filter = "CREATE USER"
            if log_sequence == '2':
                webserver_filter = "delete_db_user"
                database_filter = "DROP USER"
            if log_sequence == '3':
                webserver_filter = "db_changepwd"
                database_filter = "ALTER USER"
            if log_sequence == '4':
                webserver_filter = "create_database"
                database_filter = "CREATE DATABASE"
            if log_sequence == '5':
                webserver_filter = "delete_database"
                database_filter = "DROP DATABASE"
            if log_sequence == '6':
                webserver_filter = "create_table"
                database_filter = "CREATE TABLE"
            if log_sequence == '7':
                webserver_filter = "delete_table"
                database_filter = "DROP TABLE"
            if log_sequence == '8':
                webserver_filter = "insert_data"
                database_filter = "Moros, 999"
            if log_sequence == '9':
                webserver_filter = "delete_data "
                database_filter = "DELETE FROM"
            if log_sequence == '10':
                webserver_filter = "update_data"
                database_filter = "UPDATE"
            if log_sequence == '11':
                webserver_filter = "query_data"
                database_filter = "printall"

            for logname in os.listdir(extraction_path):
                log_path = os.path.join(extraction_path, logname)
                with open(log_path, "r") as log_file:
                    # lines = log_file.readlines()[-line_num:]
                    lines = log_file.readlines()
                if logname.__contains__("access"):
                    filtered_lines = [line for line in lines if webserver_filter in line]
                else:
                    filtered_lines = [line for line in lines if database_filter in line]
                with open(log_path, "w") as output_file:
                    output_file.writelines(filtered_lines[-12:])
            line_count = 0
            for logname in os.listdir(extraction_path):
                log_path = os.path.join(extraction_path, logname)
                if not logname.__contains__("access"):
                    with open(log_path, "r") as file:
                        for line in file:
                            line_count += 1
            for logname in os.listdir(extraction_path):
                log_path = os.path.join(extraction_path, logname)
                if logname.__contains__("access"):
                    with open(log_path, "r") as file:
                        lines = file.readlines()[-line_count:]
                    with open(log_path, "w") as file_new:
                        file_new.writelines(lines)
"""

    # 解析代码并构建AST
    tree = ast.parse(code)

    # 创建数据流图
    visitor = DataFlowVisitor()
    visitor.visit(tree)

    # 可视化数据流图
    visitor.graph.view()
