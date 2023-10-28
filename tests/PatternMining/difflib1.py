import difflib

if __name__ == '__main__':
    file1_path = 'en4217394l.log'
    file2_path = 'en4217394l.log_bak'
    database_log_filter_out = ["utf8mb4",
                               "AUTOCOMMIT",
                               "root@",
                               "COMMIT",
                               "USE user_info",
                               "Quit",
                               "---",
                               "+++",
                               "@@"]
    with open(file1_path, 'r') as file1:
        file1_contents = file1.readlines()

    with open(file2_path, 'r') as file2:
        file2_contents = file2.readlines()
    differ = list(difflib.unified_diff(file1_contents, file2_contents, lineterm='', fromfile='en4217394l.log', tofile='en4217394l.log_bak'))
    for line in differ:
        if line.startswith('-'):
            if not any(phrase in line for phrase in database_log_filter_out):
                print(line.lstrip("+"))
    # d = difflib.Differ()
    # diff = d.compare(file1_contents, file2_contents)
    # for line in diff:
    #     print(line)