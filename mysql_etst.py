from flask import Flask
from flask_sqlalchemy import  SQLAlchemy

app = Flask(__name__)

# MySQL所在主机名
HOSTNAME = "en4217394l.cidse.dhcp.asu.edu"
# MySQL监听的端口号，默认3306
PORT = 3306
# 连接MySQL的用户名，自己设置
USERNAME = "root"
# 连接MySQL的密码，自己设置
PASSWORD = "123456"
# MySQL上创建的数据库名称
DATABASE = "datebase_learn"
# 通过修改以下代码来操作不同的SQL比写原生SQL简单很多 --》通过ORM可以实现从底层更改使用的SQL
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{USERNAME}:{PASSWORD}@{HOSTNAME}:{PORT}/{DATABASE}?charset=utf8mb4"

db = SQLAlchemy(app)

# 测试是否连接成功
with app.app_context():
    with db.engine.connect() as conn:
        result = conn.execute("select 1")
        print(result.fetchone())  # (1,)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'

if __name__ == '__main__':
    app.run()