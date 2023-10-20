
import subprocess
if __name__ == '__main__':
    sysdig_output = "ls -l"
    process = subprocess.Popen([sysdig_output], shell=True)
    print(process.pid)
    pass