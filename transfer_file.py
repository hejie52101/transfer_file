# coding: utf-8
import paramiko
import os
import time
import sys
import traceback
import re
import glob
from multiprocessing import Pool
from multiprocessing import Process
import threading
# logging.basicConfig(filename='transfer_file.log', filemode='w', level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger("logger")


# sys.path.append("../../../../../Lib/")
# import ssh_cli

'''
sftp_proc and sftp_thread can upgrade multi-NE
sftp_func can upgrade one NE
Notes: Now they can not output logs in realtime
'''
def wait_end(chan, mode="oper"):
    result = ""
    if mode == "oper":
        reg = r">"
    elif mode == "login":
        reg = r".*login:"
    elif mode == "bash":
        reg = r"bash.*#"
    elif mode == "admin":
        reg = r"\$"
    else:
        reg = r"#"
    while True:
        if re.findall(reg, result[-10:]):
            break
        else:
            time.sleep(0.3)
            if chan.recv_ready():
                result += chan.recv(9999999).decode(errors='ignore')
    return chan, result

def ssh_stby(ip, username, password, ne_partition, current_partition, sha_val, clear_cfg):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, 22, username, password)
    except Exception as e:
        print("%s: ssh_stby failed." % threading.current_thread().name)
        sys.stdout.flush()
        # return 0
    chan = ssh.invoke_shell()
    time.sleep(1)
    if chan.recv_ready():
        chan.recv(9999999).decode(errors='ignore')
    if username != "npti_sp":
        if username == "root":
            print("root")
            chan.send("lsh\n")
            chan, rst_lsh = wait_end(chan)
        chan.send("\nshow chassis status|no-more\n")
        time.sleep(1)
        chan, rst_chassis = wait_end(chan)
        print("%s: Chassis info: -----> %s" % (threading.current_thread().name, rst_chassis))
        sys.stdout.flush()
        chan.send("\nstart shell\n")
        chan, rst_bash = wait_end(chan, "admin")
        # print(rst_bash)
        chan.send("su -\n")
        chan, rst_shell = wait_end(chan, "shell")
        # print(rst_shell)
        chan.send("arp\n")
        chan, rst_arp = wait_end(chan, "shell")
        # print(rst_arp)
        # re.findall("(192.168.1.[23]).*00:20:8f", rst_arp)
        if re.findall(r"169\.254\.1\.2.*00:", rst_arp):
            act_mcp = "3"
            chan.send("telnet 169.254.1.2\n")
        elif re.findall(r"169\.254\.1\.3.*00:", rst_arp):
            act_mcp = "2"
            chan.send("telnet 169.254.1.3\n")
        else:
            ssh.close()
            print("\033[0;36m%s: %s is not 1+1 mode.\033[0m" % (threading.current_thread().name, ip))
            sys.stdout.flush()
            return
        # if re.findall("msb.*operational.*stby|xsb.*operational.*stby", rst_chassis):
        #     act_mcp = "2"
        #     chan.send("telnet 169.254.1.3\n")
        # elif re.findall("msa.*operational.*stby|xsa.*operational.*stby", rst_chassis):
        #     act_mcp = "3"
        #     chan.send("telnet 169.254.1.2\n")
        # else:
        #     ssh.close()
        #     print("\033[0;36m%s: %s can not find the stby card,  it should not be 1+1 mode.\033[0m" % (threading.current_thread().name, ip))
        #     sys.stdout.flush()
        #     return
    else:
        chan.send("lsh\n")
        chan, rst_lsh = wait_end(chan)
        # print(rst_lsh)
        chan.send("\nstart shell\n")
        chan, rst_bash = wait_end(chan, "bash")
        # print(rst_bash)
        chan.send("su -\n")
        chan, rst_shell = wait_end(chan, "shell")
        # print(rst_shell)
        chan.send("arp\n")
        chan, rst_arp = wait_end(chan, "shell")
        # print(rst_arp)
        # re.findall("(192.168.1.[23]).*00:20:8f", rst_arp)
        if re.findall(r"169\.254\.1\.2.*00:", rst_arp):
            act_mcp = "3"
            chan.send("telnet 169.254.1.2\n")
        elif re.findall(r"169\.254\.1\.3.*00:", rst_arp):
            act_mcp = "2"
            chan.send("telnet 169.254.1.3\n")
        else:
            ssh.close()
            print("\033[0;36m%s: %s is not 1+1 mode.\033[0m" % (threading.current_thread().name, ip))
            sys.stdout.flush()
            return
    print("\033[0;36m%s: %s is 1+1 mode.\033[0m" % (threading.current_thread().name, ip))
    sys.stdout.flush()
    chan, login = wait_end(chan, "login")
    chan.send("root\n")
    time.sleep(1)
    chan, shell = wait_end(chan, "shell")
    print("%s: login in stby info: -----> %s" % (threading.current_thread().name, shell))
    sys.stdout.flush()
    chan.send("\nrm -rf /sdboot/" + ne_partition + "/*\n")
    chan, rm_rst = wait_end(chan, "shell")
    print("%s: Stby MCP deleted the slave partition file." % threading.current_thread().name)
    sys.stdout.flush()
    print("%s: Begin to execute copy to stby card..." % threading.current_thread().name)
    sys.stdout.flush()
    if username == "root":
        chan.send("\nscp 169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    elif username == "admin":
        chan.send("\nscp admin@169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    else:
        if clear_cfg == "true":
            chan.send("\nrm -rf /sddata/mcu/config/*\n")
            chan, rm_rst = wait_end(chan, "shell")
        chan.send("\nscp npti_sp@169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    time.sleep(1)
    rst_scp = ""
    print("%s: Coping to stby version..." % threading.current_thread().name)
    sys.stdout.flush()
    while True:
        if re.findall(r"\(yes/no\)", rst_scp[-30:]):
            chan.send("yes\n")
            time.sleep(1)
        elif re.findall(r"password:", rst_scp[-30:]):
            if username == "admin":
                chan.send("admin1\n")
            else:
                chan.send("sp&BAN42361\n")
            time.sleep(1)
        elif re.findall(r"#", rst_scp[-10:]):
            break
        time.sleep(1)
        if chan.recv_ready():
            rst_scp = chan.recv(9999999).decode(errors='ignore')
            print("%s: after scp: -----> %s" % (threading.current_thread().name, rst_scp))
            sys.stdout.flush()
    # print("%s: after scp: -----> %s" % (threading.current_thread().name, rst_scp))
    sys.stdout.flush()
    print("%s: Copy to stby card finish" % threading.current_thread().name)
    sys.stdout.flush()
    print("%s: start to sync at stby mcp..." % threading.current_thread().name)
    sys.stdout.flush()
    chan.send("\nsync\n")
    time.sleep(1)
    chan, rst_sync = wait_end(chan, "shell")
    print("\033[0;32m%s: stby mcp sync success!\033[0m" % threading.current_thread().name)
    sys.stdout.flush()
    chan.send('\nsed -i "s/' + current_partition + '/' + ne_partition + '/g" /sdboot/startup\n')
    chan, rst_sed = wait_end(chan, "shell")
    print("\033[0;32m%s: Stby MCP change master partition to %s!\033[0m" % (threading.current_thread().name, ne_partition))
    sys.stdout.flush()
    # chan.send("sha256sum /sdboot/" + ne_partition + "/*.bin\n")
    # print("%s: stby mcp start to calculate checksum..." % threading.current_thread().name)
    # sys.stdout.flush()
    # chan, sha_stby = wait_end(chan, "shell")
    # print("%s: Stby MCP sha256sum: -----> %s" % (threading.current_thread().name, sha_stby))
    # sys.stdout.flush()
    # if sha_val in sha_stby:
    #     print("\033[0;32m%s: Stby MCP checksum is OK\033[0m" % threading.current_thread().name)
    #     sys.stdout.flush()
    # else:
    #     print("\033[0;31m%s: checksum is wrong\033[0m" % threading.current_thread().name)
    #     sys.stdout.flush()
    #     chan.send("rm -rf /sdboot/" + ne_partition + "/*\n")
    #     chan, rst = wait_end(chan, "shell")
    #     print("\033[0;31m%s: Clear the Stby MCP version file!\033[0m" % threading.current_thread().name)
    #     sys.stdout.flush()
    ssh.close()


def sftp_transfer(ip, username, password, localfile, remotefile):
    try:
        t = paramiko.Transport(sock=(ip, 22))
        t.connect(username = username, password = password)
        sftp_t = paramiko.SFTPClient.from_transport(t)
    except Exception as e:
        raise Exception("\033[0;35;43m%s: sftp_transfer SSH connect failed.\033[0m" % threading.current_thread().name)
    
    print("%s: Starting to transfer version file to act mcp..." % threading.current_thread().name)
    sys.stdout.flush()
    try:
        sftp_t.put(localfile, remotefile)
        print("%s: Transfer version file to act mcp finished!" % threading.current_thread().name)
        sys.stdout.flush()
        t.close()
    except:
        print("%s: There is not enough available free space for the version file." % threading.current_thread().name)
        sys.stdout.flush()
        t.close()
        raise Exception("\033[0;35;43m%s: There is not enough available free space for the version file.\033[0m" % threading.current_thread().name)
    

def sftp_func(ip, local_path, clear_cfg, superuser):
    '''
    upgrade one NE
    '''
    # print "Run task %s (%s)..." % (ip, os.getpid())
    sys.stdout.flush()
    print("%s: thread start..." % threading.current_thread().name)
    sys.stdout.flush()
    print("%s: Thread is running..." % threading.current_thread().name)
    sys.stdout.flush()
    # local_path = r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\Version to V&V\NPTI\V7.0\V"
    # local_path = os.path.join(local_path, version)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if superuser == "false":
        try:
            ssh.connect(ip, 22, "admin", "admin1")
            username = "admin"
            password = "admin1"
            print("%s: %s has login" % (threading.current_thread().name, ip))
            sys.stdout.flush()
        except Exception as e:
            print("%s: Login failed. It will retry again." % threading.current_thread().name)
            sys.stdout.flush()
            try:
                ssh.connect(ip, 22, "admin", "admin1")
                username = "admin"
                password = "admin1"
                print("%s: %s has login" % (threading.current_thread().name, ip))
                sys.stdout.flush()
            except:
                print("%s: Login failed. It will retry again." % threading.current_thread().name)
                # print("%s: sftp_func SSH connect failed. Please confirm the NE status." % threading.current_thread().name)
                sys.stdout.flush()
                try:
                    ssh.connect(ip, 22, "root", "root")
                    username = "root"
                    password = "root"
                    print("%s: %s has login" % (threading.current_thread().name, ip))
                    sys.stdout.flush()
                except Exception as e:
                    raise Exception("\033[0;35;43m%s: Login failed. Please confirm the NE status.\033[0m" % threading.current_thread().name)
    else:
        try:
            ssh.connect(ip, 22, "npti_sp", "sp&BAN42361")
            username = "npti_sp"
            password = "sp&BAN42361"
            print("%s: %s has login" % (threading.current_thread().name, ip))
            sys.stdout.flush()
        except Exception as e:
            print("%s: Login failed. It will retry one time." % threading.current_thread().name)
            sys.stdout.flush()
            try:
                ssh.connect(ip, 22, "npti_sp", "sp&BAN42361")
                username = "npti_sp"
                password = "sp&BAN42361"
                print("%s: %s has login" % (threading.current_thread().name, ip))
                sys.stdout.flush()
            except:
                raise Exception("\033[0;35;43m%s: Login failed. Please confirm the NE status.\033[0m" % threading.current_thread().name)

    if username != "npti_sp":
        chan = ssh.invoke_shell()
        time.sleep(1)
        chan.recv(9999999).decode(errors='ignore')
        if username == "root":
            chan.send("lsh\n")
            chan, rst_lsh = wait_end(chan)
        chan.send("\nshow version|no-more\n")
        time.sleep(1)
        chan, rst_version = wait_end(chan)
        chan.send("\nshow system bank|no-more\n")
        time.sleep(1)
        chan, partition = wait_end(chan)
        # ssh.close()
        print("%s: version info: -----> %s" % (threading.current_thread().name, rst_version))
        sys.stdout.flush()
        # print("%s: ne partition: -----> %s" % (threading.current_thread().name, partition))
        # sys.stdout.flush()
        if "Up-Partition" in partition:
            ne_partition = "down"
        elif "Down-Partition" in partition:
            ne_partition = "up"
        else:
            raise Exception("\033[0;35;43m%s: Partition get failed, please check it by yourself.\033[0m" % threading.current_thread().name)
        print("%s: ne slave partition: -----> %s" % (threading.current_thread().name, ne_partition))
        sys.stdout.flush()
        if re.findall(r"Ne Type.*NPT-1800.*2\+0", rst_version):
            ne_type = "1800_2p0"
            try:
                localfile = os.path.join(local_path, re.findall(r"NPT1800_Emb_2p0_\d+\.bin", ", ".join(os.listdir(local_path)))[0])
            except:
                raise Exception("\033[0;35;43m%s: The NPT-1800 2+0 version file can not be found. Please confirm the version file.\033[0m" % threading.current_thread().name)
            remotefile = "/sdboot/" + ne_partition + "/NPT1800_Emb.bin"
        else:
            ne_type = re.findall(r"Ne Type.*NPT-(\w*)", rst_version)[0]
            try:
                localfile = os.path.join(local_path, re.findall("NPT"+ne_type+r"_Emb_\d+\.bin", ", ".join(os.listdir(local_path)))[0])
            except:
                raise Exception("\033[0;35;43m%s: The %s version file can not be found. Please confirm the version file.\033[0m" % (threading.current_thread().name, ne_type))
            remotefile = "/sdboot/" + ne_partition + "/NPT" + ne_type + "_Emb.bin"
    else:
        stdin, stdout, stderr = ssh.exec_command("cat /sdboot/startup")
        startup = re.findall(r"/.*\.bin", stdout.read().decode(errors='ignore'))[0]
        if "up" in startup:
            ne_partition = "down"
        else:
            ne_partition = "up"
        ne_type = re.findall(r"NPT(\w*)_", startup)[0]
        remotefile = "/sdboot/" + ne_partition + "/NPT" + ne_type + "_Emb.bin"
        localfile = glob.glob(local_path+"\\"+startup.split("/")[-1].split(".")[0]+"_?????.bin")[0]

    print("%s: ne_type: -----> %s" % (threading.current_thread().name, ne_type))
    sys.stdout.flush()
    print("\033[0;32m%s: localfile: -----> %s\033[0m" % (threading.current_thread().name, localfile))
    sys.stdout.flush()
    print("\033[0;32m%s: remotefile: -----> %s\033[0m" % (threading.current_thread().name, remotefile))
    sys.stdout.flush()

    try:
        stdin, stdout, stderr = ssh.exec_command("rm -rf /sdboot/" + ne_partition + "/*")
        rm_rst = stdout.read().decode(errors='ignore')
        print("%s: Act MCP deleted the slave partition file." % threading.current_thread().name)
        sys.stdout.flush()
        ssh.close()
        sftp_transfer(ip, username, password, localfile, remotefile)
    except Exception as e:
        raise e

    try:
        ssh.connect(ip, 22, username, password)
        print("%s: start to sync at act mcp" % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("sync")
        print("\033[0;32m%s: act mcp sync success: -----> %s\033[0m" % (threading.current_thread().name, stdout.read().decode(errors='ignore')))
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("sha256sum " + remotefile)
        checksum = stdout.read().decode(errors='ignore')
        print("%s: sha256sum: -----> %s" % (threading.current_thread().name, checksum))
        sys.stdout.flush()
    except Exception as e:
        raise Exception("\033[0;35;43m%s: Main sync SSH connect failed.\033[0m" % threading.current_thread().name)

    if ne_type == "1800":
        shafile = localfile[:-9] + "1p1_sha256"
    else:
        shafile = localfile[:-9] + "sha256"

    try:
        f = open(shafile)
        sha_val = f.read()
        f.close()
    except Exception as e:
        raise Exception("\033[0;35;43m%s: Open local SHA file failed.\033[0m" % threading.current_thread().name)

    print("%s: local_sha256: -----> %s" % (threading.current_thread().name, sha_val))
    sys.stdout.flush()
    if sha_val in checksum:
        print("\033[0;32m%s: checksum is OK\033[0m" % threading.current_thread().name)
        sys.stdout.flush()
        ssh.close()
    else:
        print("\033[0;31m%s: checksum is wrong\033[0m" % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("rm -f " + remotefile)
        stdout.read().decode(errors='ignore')
        ssh.close()
        raise Exception("\033[0;35;43m%s: checksum is wrong\033[0m" % threading.current_thread().name)
    
    if ne_partition == "down":
        current_partition = "up"
    else:
        current_partition = "down"

    if ne_type != "1800_2p0":
        print("%s: Check the standby card..." % threading.current_thread().name)
        sys.stdout.flush()
        ssh_stby(ip, username, password, ne_partition, current_partition, sha_val, clear_cfg)

    try:
        ssh.connect(ip, 22, username, password)
    except Exception as e:
        raise Exception("\033[0;35;43m%s: Reset SSH connect failed.\033[0m" % threading.current_thread().name)
    chan = ssh.invoke_shell()
    stdin, stdout, stderr = ssh.exec_command('sed -i "s/' + current_partition + '/' + ne_partition + '/g" /sdboot/startup')
    stdout.read().decode(errors='ignore')
    print("\033[0;32m%s: Act MCP change master partition to %s!\033[0m" % (threading.current_thread().name, ne_partition))
    sys.stdout.flush()
    time.sleep(1)
    chan.recv(9999).decode(errors='ignore')
    if username == "root":
        chan.send("lsh\n")
        chan, rst_lsh = wait_end(chan)
        # print(rst_lsh)
    if clear_cfg == "false":
        chan.send("\nrequest reset ne\n")
    else:
        chan.send("\nrequest reset no-recovery-sdh\n")
    reset_rst = ""
    while True:
        if re.findall(r"\(no\)", reset_rst[-30:]):
            # 执行复位操作
            chan.send("yes\n")
            time.sleep(1)
            break
        else:
            time.sleep(1)
            if chan.recv_ready():
                reset_rst += chan.recv(9999999).decode(errors='ignore')
    time.sleep(1)
    if chan.recv_ready():
        reset_rst += chan.recv(9999).decode(errors='ignore')
    print("%s: NE will reset: -----> %s" % (threading.current_thread().name, reset_rst))
    sys.stdout.flush()
    ssh.close()
    print("\033[0;32m%s: thread finished.\033[0m" % threading.current_thread().name)
    sys.stdout.flush()

class my_thread(threading.Thread):
    def __init__(self, ip, local_path, clear_cfg, superuser):
        threading.Thread.__init__(self)
        self.name = "Thread_" + ip
        self.ip = ip
        self.local_path = local_path
        self.clear_cfg = clear_cfg
        self.superuser = superuser
        self.exitcode = 0
        self.exception = None
        self.exc_traceback = ''
    def run(self):
        try:
            sftp_func(self.ip, self.local_path, self.clear_cfg, self.superuser)
        except Exception as e:
            self.exitcode = 1
            self.exc_traceback = ''.join(traceback.format_exception(*sys.exc_info()))

def sftp_thread(ip_list, local_path, clear_cfg, superuser):
    print("Thread %s is running..." % threading.current_thread().name)
    sys.stdout.flush()
    for ip in ip_list:
        locals()["t_"+ip] = my_thread(ip, local_path, clear_cfg, superuser)
        locals()["t_"+ip].start()
    for ip in ip_list:
        locals()["t_"+ip].join()
    for ip in ip_list:
        if locals()["t_"+ip].exitcode == 1:
            raise Exception(locals()["t_"+ip].exc_traceback)
    print("Thread %s ended." % threading.current_thread().name)
    sys.stdout.flush()
def sftp_proc(ip_list, username, password, version):
    print("Parent process %s is running..." % os.getpid())
    sys.stdout.flush()
    for ip in ip_list:
        locals()["p_"+ip]=Process(target=sftp_func, args=(ip, username, password, version))
        locals()["p_"+ip].start()
    for ip in ip_list:
        locals()["p_"+ip].join()
    # p = Pool(len(ip_list))
    # for ip in ip_list:
    #     p.apply_async(sftp_func, args=(ip, username, password, version))
    # print("%s: Waiting for all subprocesses done..." % os.getpid())
    sys.stdout.flush()
    # p.close()
    p.join()
    print("%s: All subprocesses done." % os.getpid())
    sys.stdout.flush()

if __name__ == '__main__':
    version = sys.argv[1]
    # print(version)
    # sys.stdout.flush()
    ip_list = sys.argv[2].replace(" ", "").split(",")
    clear_cfg = sys.argv[3]
    superuser = sys.argv[4]
    # version = "7.5.614"
    # ip_list = "200.200.121.123".replace(" ", "").split(",")
    # clear_cfg = "false"
    # del_ver = "false"
    # superuser = "false"
    if not version:
        raise Exception("\033[0;35;43mThe version is blank, please type it!\033[0m")
    if not "".join(ip_list):
        raise Exception("\033[0;35;43mThe NE IP is blank, please type it!\033[0m")
    if not re.findall(r"[nN]etstore|172\.18\.104\.44", version):
        vv = re.findall(r"(\d)\.(\d)\.(0\d\d)", version)
        temp = re.findall(r"(\d)\.(\d)\.([56]\d\d)", version)
        temp_cmcc = re.findall(r"(\d)\.(\d)\.(7\d\d)", version)
        daily = re.findall(r"(\d)\.(\d)\.(8\d\d)", version) #V7.5.846
        daily_cmcc = re.findall(r"(\d)\.(\d)\.(9\d\d)", version)
        daily_date = re.findall(r"^\d{4}-\d{2}-\d{2}", version)
        daily_cmcc_date = re.findall(r"^CMCC-(\d{4}-\d{2}-\d{2})", version)
        # sys.stdout.flush()
        if vv:
            version_dir = os.path.join(r"\\Netstore-ch\r&d tn china\R&D_Server\Version Management\Dev_Version\Version to V&V\NPTI\V" + vv[0][0] + "." + vv[0][1], "V" + vv[0][0] + "." + vv[0][1] + "." + vv[0][2])
            print(version_dir)
            sys.stdout.flush()
        elif temp:
            version_dir = os.path.join(r"\\Netstore-ch\r&d tn china\R&D_Server\Version Management\Dev_Version\TempVersion\NPTI\V" + temp[0][0] + "." + temp[0][1], ".".join(temp[0]) + "*")
        elif temp_cmcc:
            version_dir = os.path.join(r"\\Netstore-ch\r&d tn china\R&D_Server\Version Management\Dev_Version\TempVersion\NPTI\V" + temp_cmcc[0][0] + "." + temp_cmcc[0][1] + "-CMCC", ".".join(temp_cmcc[0]) + "*")
        elif daily:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI\*", "NPT*" + "".join(daily[0]) + ".bin")
            file_test = glob.glob(version_dir)
            if file_test:
                version_dir = os.path.dirname(file_test[0])
            else:
                raise Exception("\033[0;35;43mThe version is not found, please type again!\033[0m")
        elif daily_cmcc:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI-CMCC\*", "NPT*" + "".join(daily_cmcc[0]) + ".bin")
            file_test = glob.glob(version_dir)
            if file_test:
                version_dir = os.path.dirname(file_test[0])
            else:
                raise Exception("\033[0;35;43mThe version is not found, please type again!\033[0m")
        elif daily_date:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI", daily_date[0])
        elif daily_cmcc_date:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI-CMCC", "".join(daily_cmcc_date[0]))
        else:
            raise Exception("\033[0;35;43mThe version is not found, please type again!\033[0m")
        version_dir = glob.glob(version_dir)
        if version_dir:
            if os.stat(version_dir[0]).st_ctime > os.stat(version_dir[-1]).st_ctime:
                    version_dir = version_dir[0]
            else:
                version_dir = version_dir[-1]
        else:
            raise Exception("\033[0;35;43mThe version is not found, please type again!\033[0m")
    else:
        version_dir = version
    print("version path: " + version_dir)
    sys.stdout.flush()
    try:
        sftp_thread(ip_list, version_dir, clear_cfg, superuser)
    except Exception as e:
        raise e
    
