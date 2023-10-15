# -* - coding: UTF-8 -* -
# ! /usr/bin/python
# important: please run python server with sudo command, since normal user cannot reach sql_log_path
# 请在服务器上使用用sudo带起此python文件，因为数据库的log普通用户拿不到
import os.path as path
from flask import Flask, render_template,request, send_file
import logging
import pymysql
import sys
import psycopg2
import redis

app = Flask("sysdig_app_log")
app.config['MYSQL_HOST'] = 'en4217394l.cidse.dhcp.asu.edu'  # 数据库地址
app.config['MYSQL_PORT'] = 3306  # 数据库端口
app.config['MYSQL_USER'] = 'root'  # 数据库用户名
app.config['MYSQL_PASSWORD'] = '123456'  # 数据库密码
app.config['MYSQL_CHARSET'] = 'utf8mb4'  # 数据库编码
if sys.platform.startswith('linux'):
    mysql_log_path = "/var/lib/mysql/en4217394l.log"
    postgresql_log_path = "/var/log/pg_log/postgresql-2023-10-14_000000.log"
    redis_log_path = "/var/log/redis/redis-server.log"
else:
    mysql_log_path = "static/var/lib/mysql/en4217394l.log"
    postgresql_log_path = "static/var/log/pg_log/postgresql-2023-10-02_010707.log"
    redis_log_path = "static/var/log/pg_log/postgresql-2023-10-02_010707.log"

@app.route('/', methods=['GET'])
def button_page():
    if sys.platform.startswith('linux'):
        init_backend_config()
    return render_template("button_page.html")

def init_backend_config():
    #1. update postgresql log position, since it will change every day
    # stderr /var/log/pg_log/postgresql-2023-10-14_000000.log
    global postgresql_log_path
    with open("/var/lib/postgresql/15/main/current_logfiles", "r") as postgresql_log_assign:
        first_line = postgresql_log_assign.readline()
    postgresql_log_path = first_line[len("stderr "):].rstrip('\n')

@app.route('/submit_everything', methods=['POST'])
def submit_everything():
    database_select = request.form.get("database_select")
    if database_select == "mysql":
        pass
    elif database_select == "postgresql":
        pass
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    pass

def process_mysql_sytax(sytax):
    app.config['MYSQL_DB'] = 'user_info'  # 数据库名称
    mysql = pymysql.connect(host=app.config['MYSQL_HOST'],
                            port=app.config['MYSQL_PORT'],
                            user=app.config['MYSQL_USER'],
                            password=app.config['MYSQL_PASSWORD'],
                            db=app.config['MYSQL_DB'],
                            charset=app.config['MYSQL_CHARSET'])
    cursor = mysql.cursor(cursor=pymysql.cursors.DictCursor)
    # cursor = mysql.cursor()
    sql = sytax
    sql_list = [part.strip() for part in sql.split(';') if part.strip()]
    for sqll in sql_list:
        cursor.execute(sqll)
    if cursor.rowcount > 0:
        sql_return = cursor.fetchall()
    else:
        sql_return = "No results returned by the query."
    mysql.commit()  # 修改数据之前要记得commit不然不会成功
    mysql.close()
    sql_return_str = ""
    for sql_return_item in sql_return:
        sql_return_str = "%s%s\n" % (sql_return_str, str(sql_return_item).rstrip("}").lstrip("{"))
    return sql_return_str

def process_postgresql_sytax(sytax):
    # postgresql默认指定了数据库"postgres"
    postgresql = psycopg2.connect(host=app.config['MYSQL_HOST'],
                            port=5432,
                            user='postgres',
                            password='1234',
                            database='postgres')
    postgresql.autocommit = True
    cursor = postgresql.cursor()
    sql = sytax
    sql_list = [part.strip() for part in sql.split(';') if part.strip()]
    for sqll in sql_list:
        cursor.execute(sqll)
    if cursor.rowcount > 0 and not sql.__contains__(" company "):
        sql_return = cursor.fetchall()
    else:
        sql_return = "No results returned by the query."
    # postgresql.commit()  # 修改数据之前要记得commit不然不会成功
    postgresql.close()
    sql_return_str = ""
    for sql_return_item in sql_return:
        sql_return_str = "%s%s\n" % (sql_return_str, str(sql_return_item).rstrip("}").lstrip("{"))
    return sql_return_str

def process_redis_sytax(sytax):
    redis_conn = redis.Redis(host=app.config['MYSQL_HOST'], port=6379, db=0)
    sql_return_str = ""
    cursor = '0'
    redis_syntax = sytax.split("?")[0]
    redis_action = sytax.split("?")[1]
    if redis_action == "query":
        while True:
            cursor, data = redis_conn.scan(cursor=cursor)
            for key in data:
                value = redis_conn.get(key).decode('utf-8')
                sql_return_str = "%sKey: %s, Value: %s\n" % (sql_return_str, key,value)
            if cursor == 0:
                break  # When cursor is '0', we've iterated through all keys
    elif redis_action == "delete":
        redis_conn.delete(redis_syntax.split(",")[0].strip())
    else:
        redis_conn.set(redis_syntax.split(",")[0].strip(), redis_syntax.split(",")[1].strip())

    redis_conn.connection_pool.disconnect()
    return sql_return_str
def process_sql_log(sql_log_path):
    with open(sql_log_path, "r") as sql_log_file:
        all_lines = sql_log_file.readlines()
        last_200_lines = all_lines[-200:]
    return "".join(last_200_lines)

# if the user exit, the create action will fail and the front end will respond nothing/
@app.route('/create_db_user', methods=['POST'])
def create_db_user():
    database_select = request.form.get("database_select")
    result_dict = {}
    db_uname = request.form.get("db_uname")
    db_pwd = request.form.get("db_pwd")
    if database_select == "mysql":
        sql_sytax = "CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';" % (db_uname, db_pwd)
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "CREATE USER '%s'@'localhost' IDENTIFIED BY '%s';" % (db_uname, db_pwd)
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/query_db_user', methods=['POST'])
def query_db_user():
    database_select = request.form.get("database_select")
    result_dict = {}
    if database_select == "mysql":
        sql_sytax = "SELECT User, Host FROM mysql.user;"
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "SELECT usename FROM pg_user;"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/delete_db_user', methods=['POST'])
def delete_db_user():
    database_select = request.form.get("database_select")
    result_dict = {}
    db_uname_delete = request.form.get("db_uname_delete")
    if database_select == "mysql":
        sql_sytax = "DROP USER '%s'@'localhost';" % db_uname_delete
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "DROP USER %s;" % db_uname_delete
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/db_changepwd', methods=['POST'])
def db_changepwd():
    database_select = request.form.get("database_select")
    result_dict = {}
    db_uname_change = request.form.get("db_uname_change")
    db_pwd_change = request.form.get("db_pwd_change")
    if database_select == "mysql":
        sql_sytax = "ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';" % (db_uname_change, db_pwd_change)
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "ALTER USER %s WITH PASSWORD '%s';" % (db_uname_change, db_pwd_change)
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/query_db_user_password', methods=['POST'])
def query_db_user_password():
    database_select = request.form.get("database_select")
    result_dict = {}
    if database_select == "mysql":
        sql_sytax = "SELECT * FROM mysql.user;"
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "SELECT usename, passwd FROM pg_shadow;"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/create_database', methods=['POST'])
def create_database():
    database_select = request.form.get("database_select")
    result_dict = {}
    create_database_name = request.form.get("create_database_name")
    if database_select == "mysql":
        sql_sytax = "CREATE DATABASE %s;" % create_database_name
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "CREATE DATABASE %s;" % create_database_name
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/query_database', methods=['POST'])
def query_database():
    database_select = request.form.get("database_select")
    result_dict = {}
    if database_select == "mysql":
        sql_sytax = "SHOW DATABASES;"
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "SELECT datname FROM pg_database;"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/delete_database', methods=['POST'])
def delete_database():
    database_select = request.form.get("database_select")
    result_dict = {}
    delete_database_name = request.form.get("delete_database_name")
    if database_select == "mysql":
        sql_sytax = "DROP DATABASE %s;" % delete_database_name
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "DROP DATABASE %s;" % delete_database_name
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/create_table', methods=['POST'])
def create_table():
    database_select = request.form.get("database_select")
    result_dict = {}
    create_table_name = request.form.get("create_table_name")
    create_table_sql = "USE user_info;CREATE TABLE %s (employee_id INT AUTO_INCREMENT PRIMARY KEY,first_name VARCHAR(50),last_name VARCHAR(50),email VARCHAR(100),hire_date DATE);" % create_table_name
    if database_select == "mysql":
        sql_sytax = create_table_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "CREATE TABLE %s ( employee_id serial PRIMARY KEY, first_name VARCHAR (50), last_name VARCHAR (50), email VARCHAR (100), hire_date DATE );" % create_table_name
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/query_table', methods=['POST'])
def query_table():
    database_select = request.form.get("database_select")
    result_dict = {}
    create_table_sql = "USE user_info;SHOW tables;"
    if database_select == "mysql":
        sql_sytax = create_table_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/delete_table', methods=['POST'])
def delete_table():
    database_select = request.form.get("database_select")
    result_dict = {}
    delete_table_name = request.form.get("delete_table_name")
    create_table_sql = "USE user_info;DROP TABLE %s;" % delete_table_name
    if database_select == "mysql":
        sql_sytax = create_table_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "DROP TABLE %s;" % delete_table_name
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        pass
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/insert_data', methods=['POST'])
def insert_data():
    database_select = request.form.get("database_select")
    result_dict = {}
    insert_sql = request.form.get("insert_sql")
    if database_select == "mysql":
        sql_sytax = insert_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "INSERT INTO company (name, age) VALUES ('ppp', '30');"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        # add action to redis
        sql_sytax = "%s?insert" % insert_sql
        sql_result = process_redis_sytax(sql_sytax)
        sql_log = process_sql_log(redis_log_path)
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/query_data', methods=['POST'])
def query_data():
    database_select = request.form.get("database_select")
    result_dict = {}
    query_sql = request.form.get("query_sql")
    if database_select == "mysql":
        sql_result = process_mysql_sytax(query_sql)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        query_sql = "select * from company;"
        sql_result = process_postgresql_sytax(query_sql)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        # add action to redis
        sql_sytax = "%s?query" % query_sql
        sql_result = process_redis_sytax(sql_sytax)
        sql_log = process_sql_log(redis_log_path)
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/delete_data', methods=['POST'])
def delete_data():
    database_select = request.form.get("database_select")
    result_dict = {}
    delete_sql = request.form.get("delete_sql")
    if database_select == "mysql":
        sql_sytax = delete_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "DELETE FROM company WHERE id = (SELECT max(id) FROM company);"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        # add action to redis
        sql_sytax = "%s?delete" % delete_sql
        sql_result = process_redis_sytax(sql_sytax)
        sql_log = process_sql_log(redis_log_path)
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200

@app.route('/update_data', methods=['POST'])
def update_data():
    database_select = request.form.get("database_select")
    result_dict = {}
    update_sql = request.form.get("update_sql")
    if database_select == "mysql":
        sql_sytax = update_sql
        sql_result = process_mysql_sytax(sql_sytax)
        sql_log = process_sql_log(mysql_log_path)
    elif database_select == "postgresql":
        sql_sytax = "UPDATE company SET age = 21 WHERE id = (SELECT max(id) FROM company);"
        sql_result = process_postgresql_sytax(sql_sytax)
        sql_log = process_sql_log(postgresql_log_path)
    elif database_select == "redis":
        # add action to redis
        sql_sytax = "%s?update" % update_sql
        sql_result = process_redis_sytax(sql_sytax)
        sql_log = process_sql_log(redis_log_path)
    elif database_select == "mongodb":
        pass
    elif database_select == "influxdb":
        pass
    elif database_select == "neo4j":
        pass
    result_dict["sql_result"] = sql_result
    result_dict["sql_log"] = sql_log
    return result_dict, 200


@app.route('/button_page_function', methods=['POST'])
def button_page_function():
    user_ip = request.remote_addr
    app.config['MYSQL_DB'] = 'user_info'  # 数据库名称
    mysql = pymysql.connect(host=app.config['MYSQL_HOST'],
                            port=app.config['MYSQL_PORT'],
                            user=app.config['MYSQL_USER'],
                            password=app.config['MYSQL_PASSWORD'],
                            db=app.config['MYSQL_DB'],
                            charset=app.config['MYSQL_CHARSET'])
    username = request.form.get("uname")
    password = request.form.get("pwd")
    cursor = mysql.cursor(cursor=pymysql.cursors.DictCursor)
    sql = "SELECT name, password FROM usersinfo"
    cursor.execute(sql)
    name_password = cursor.fetchall()
    mysql.close()
    for name_password_dict in name_password:
        if username == name_password_dict["name"] and password == name_password_dict["password"]:
            logging.debug("user %s login success, ip = %s" % (username, user_ip))
            return "Login Success", 200
    logging.info("the username %s from ip %s does not exist, show hint" % (username, user_ip))
    return "Login Failed, please register first", 200

@app.route('/registerform_str', methods=['POST'])
def registerform_str():
    user_ip = request.remote_addr
    app.config['MYSQL_DB'] = 'user_info'  # 数据库名称
    mysql = pymysql.connect(host=app.config['MYSQL_HOST'],
                            port=app.config['MYSQL_PORT'],
                            user=app.config['MYSQL_USER'],
                            password=app.config['MYSQL_PASSWORD'],
                            db=app.config['MYSQL_DB'],
                            charset=app.config['MYSQL_CHARSET'])
    username = request.form.get("uname")
    password = request.form.get("pwd")
    cursor = mysql.cursor(cursor=pymysql.cursors.DictCursor)
    sql = "SELECT name, password FROM usersinfo;"
    cursor.execute(sql)
    name_password = cursor.fetchall()
    for name_password_dict in name_password:
        if username == name_password_dict["name"]:
            sql = "UPDATE usersinfo SET password = '%s' WHERE name = '%s';" % (password, username)
            cursor.execute(sql)
            mysql.commit()
            mysql.close()
            logging.debug("user %s update success, ip = %s" % (username, user_ip))
            return "update passowrd success", 200
    sql = "INSERT INTO usersinfo (name, password) VALUES ('%s', '%s');" % (username, password)
    cursor.execute(sql)
    mysql.commit()
    mysql.close()
    logging.debug("user %s register success, ip = %s" % (username, user_ip))
    return "register success", 200

@app.route('/download_file', methods=['GET'])
def download_file():
    user_ip = request.remote_addr
    filename = request.args.get("filename")
    file_path = path.join("static", filename)
    logging.debug("user ip = %s fetched file" % user_ip)
    return send_file(file_path, as_attachment=True), 200

@app.route('/exe_sql', methods=['POST'])
def exe_sql():
    sql_syntax = request.form.get("sql_syntax")
    print(sql_syntax)
    result_dict = {
        "key": sql_syntax
    }
    return result_dict, 200

if __name__ == '__main__':
    handler = logging.FileHandler('flask.log', encoding='UTF-8')
    handler.setLevel(logging.DEBUG)
    logging_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')
    handler.setFormatter(logging_format)
    app.logger.addHandler(handler)
    app.run(host='127.0.0.1', port=5001, debug=True)