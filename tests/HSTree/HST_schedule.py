import schedule
import subprocess
from py2neo import Graph
import time
graph = Graph('http://localhost:7474/', username='neo4j', password='2w2w2w2w')

sysdig_output = "system_log_a.txt"
# 主被倒换
def run_command():
    global sysdig_output
    if sysdig_output == "system_log_a.txt":
        sysdig_output = "system_log_b.txt"
        hst_anlysis = "system_log_a.txt"
    else:
        sysdig_output = "system_log_a.txt"
        hst_anlysis = "system_log_b.txt"
    hst_anlysis_command = 'python3 HST.py %s' % hst_anlysis
    print(hst_anlysis_command)
    print(time.time())
    subprocess.Popen(hst_anlysis_command, shell=True)
    sysdig_command = 'sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > ' + sysdig_output
    print(sysdig_command)
    print(time.time())
    process_sys = subprocess.Popen(sysdig_command, shell=True)
    # 这里依旧不对，hst还是等sysdig跑完再开始的，所以如何并行跑？sysdig如何精确的知道自己跑了多久，精确间隔
    try:
        process_sys.wait(timeout=1199)
    except subprocess.TimeoutExpired:
        subprocess.run("killall sysdig", shell=True)

def init():
    graph.run("MATCH (n) DETACH DELETE n;")
    cmds = '''
MERGE (n:root {name:"root"});
MERGE (n:evnt_p {name:"Process"});
MERGE (n:evnt_f {name:"File"});
MERGE (n:evnt_n {name:"network"});
MERGE (n:oper_p {name:"Start"});
MERGE (n:oper_p {name:"End"});
MERGE (n:oper_f {name:"Create"});
MERGE (n:oper_f {name:"Modify"});
MERGE (n:oper_f {name:"Delete"});
MERGE (n:oper_f {name:"Rename"});
MERGE (n:oper_n {name:"Connect"});
MERGE (n:oper_n {name:"Listen"});
MATCH(n:root{name:"root"}) MATCH(a:evnt_p{name:"Process"}) MERGE(n)-[:r2e]->(a);
MATCH(n:root{name:"root"}) MATCH(a:evnt_f{name:"File"}) MERGE(n)-[:r2e]->(a);
MATCH(n:root{name:"root"}) MATCH(a:evnt_n{name:"network"}) MERGE(n)-[:r2e]->(a);

MATCH(n:evnt_p{name:"Process"}) MATCH(a:oper_p{name:"Start"}) MERGE(n)-[:e2o]->(a);
MATCH(n:evnt_p{name:"Process"}) MATCH(a:oper_p{name:"End"}) MERGE(n)-[:e2o]->(a);

MATCH(n:evnt_f{name:"File"}) MATCH(a:oper_f{name:"Create"}) MERGE(n)-[:e2o]->(a);
MATCH(n:evnt_f{name:"File"}) MATCH(a:oper_f{name:"Modify"}) MERGE(n)-[:e2o]->(a);
MATCH(n:evnt_f{name:"File"}) MATCH(a:oper_f{name:"Delete"}) MERGE(n)-[:e2o]->(a);
MATCH(n:evnt_f{name:"File"}) MATCH(a:oper_f{name:"Rename"}) MERGE(n)-[:e2o]->(a);

MATCH(n:evnt_n{name:"network"}) MATCH(a:oper_n{name:"Connect"}) MERGE(n)-[:e2o]->(a);
MATCH(n:evnt_n{name:"network"}) MATCH(a:oper_n{name:"Listen"}) MERGE(n)-[:e2o]->(a);


CREATE CONSTRAINT ON (f:attr_f) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:attr_p) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:attr_n) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:proc_f) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:proc_n) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:proc_p) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:proc_sp) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:oper_p) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:oper_f) ASSERT f.name IS UNIQUE;
CREATE CONSTRAINT ON (f:oper_n) ASSERT f.name IS UNIQUE;
'''
    #设置主键，用于加速

    for cmd in cmds.split("\n"):
        if cmd != '':
            graph.run(cmd)
    # first time, run sysdig 20 min
    first_command = 'sysdig -p"%evt.num %evt.rawtime.s.%evt.rawtime.ns %evt.cpu %proc.name (%proc.pid) %evt.dir %evt.type cwd=%proc.cwd %evt.args latency=%evt.latency" -s 200 evt.type!=switch and proc.name!=sysdig > system_log_a.txt'
    process = subprocess.Popen(first_command, shell=True)
    try:
        process.wait(timeout=120)
    except:
        subprocess.run("kill -9 %s %s" % (process.pid, process.pid+1), shell=True)

if __name__ == '__main__':
    init()
    time.sleep(120)
    schedule.every(20).minutes.do(run_command)
    while True:
        schedule.run_pending()