# coding: utf-8
import paramiko
import os
import time
import sys
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
        reg = r".*@.*>"
    elif mode == "login":
        reg = r".*login:"
    elif mode == "bash":
        reg = r"bash.*#"
    else:
        reg = r".*@.*#"
    while True:
        if re.findall(reg, result[-20:]):
            break
        else:
            time.sleep(1)
            if chan.recv_ready():
                result += chan.recv(9999999).decode()
    return chan, result

def ssh_stby(ip, username, password, ne_partition):
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
        print(chan.recv(9999999).decode())
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
        if re.findall("msb.*operational.*stby|xsb.*operational.*stby", rst_chassis):
            act_mcp = "2"
            chan.send("telnet 169.254.1.3\n")
        elif re.findall("msa.*operational.*stby|xsa.*operational.*stby", rst_chassis):
            act_mcp = "3"
            chan.send("telnet 169.254.1.2\n")
        else:
            ssh.close()
            print("%s: %s is not 1+1 mode." % (threading.current_thread().name, ip))
            sys.stdout.flush()
            return
    else:
        chan.send("lsh\n")
        chan, rst_lsh = wait_end(chan)
        print(rst_lsh)
        chan.send("\nstart shell\n")
        chan, rst_bash = wait_end(chan, "bash")
        print(rst_bash)
        chan.send("su -\n")
        chan, rst_shell = wait_end(chan, "shell")
        print(rst_shell)
        chan.send("arp\n")
        chan, rst_arp = wait_end(chan, "shell")
        print(rst_arp)
        # re.findall("(192.168.1.[23]).*00:20:8f", rst_arp)
        if re.findall(r"169\.254\.1\.2.*00:", rst_arp):
            act_mcp = "3"
            print(act_mcp)
            chan.send("telnet 169.254.1.2\n")
        elif re.findall(r"169\.254\.1\.3.*00:", rst_arp):
            act_mcp = "2"
            print(act_mcp)
            chan.send("telnet 169.254.1.3\n")
        else:
            ssh.close()
            print("%s: %s is not 1+1 mode." % (threading.current_thread().name, ip))
            sys.stdout.flush()
            return
    print("%s: %s is 1+1 mode." % (threading.current_thread().name, ip))
    chan, login = wait_end(chan, "login")
    chan.send("root\n")
    time.sleep(1)
    chan, shell = wait_end(chan, "shell")
    print("%s: login in stby info: -----> %s" % (threading.current_thread().name, shell))
    sys.stdout.flush()
    print("%s: Begin to execute copy to stby card..." % threading.current_thread().name)
    sys.stdout.flush()
    if username == "root":
        chan.send("\nscp 169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    elif username == "admin":
        chan.send("\nscp admin@169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    else:
        chan.send("\nscp npti_sp@169.254.1." + act_mcp + ":/sdboot/" + ne_partition + "/NPT*.bin /sdboot/" + ne_partition + "\n")
    time.sleep(1)
    rst_scp = ""
    print("%s: Coping to stby version..." % threading.current_thread().name)
    sys.stdout.flush()
    while True:
        if re.findall(r"\(yes/no\)", rst_scp[-15:]):
            chan.send("yes\n")
            time.sleep(1)
        elif re.findall(r"password:", rst_scp[-15:]):
            if username == "admin":
                chan.send("admin1\n")
            else:
                chan.send("sp&BAN42361\n")
            time.sleep(1)
        elif re.findall(r".*@.*#", rst_scp[-15:]):
            break
        time.sleep(1)
        if chan.recv_ready():
            rst_scp = chan.recv(9999999).decode()
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
    ssh.close()
    print("%s: stby mcp sync success!" % threading.current_thread().name)
    sys.stdout.flush()
    return 1


def sftp_transfer(ip, username, password, localfile, remotefile, mode="put"):
    try:
        t = paramiko.Transport(sock=(ip, 22))
        t.connect(username = username, password = password)
        sftp_t = paramiko.SFTPClient.from_transport(t)
    except Exception as e:
        print("%s: sftp_transfer SSH connect failed." % threading.current_thread().name)
        sys.stdout.flush()
        raise
    
    print("%s: Starting to transfer version file to act mcp..." % threading.current_thread().name)
    sys.stdout.flush()
    if mode == "put":
        sftp_t.put(localfile, remotefile)
    else:
        sftp_t.get(remotefile, localfile)
    print("%s: Transfer version file to act mcp finished!" % threading.current_thread().name)
    sys.stdout.flush()
    t.close()

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
                    print("%s: Login failed. Please confirm the NE status." % threading.current_thread().name)
                    sys.stdout.flush()
                    return
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
                print("%s: Login failed. Please confirm the NE status." % threading.current_thread().name)
                # print("%s: sftp_func SSH connect failed. Please confirm the NE status." % threading.current_thread().name)
                sys.stdout.flush()
                return

    if username != "npti_sp":
        chan = ssh.invoke_shell()
        time.sleep(1)
        chan.recv(9999999).decode()
        if username == "root":
            chan.send("lsh\n")
            chan, rst_lsh = wait_end(chan)
        chan.send("\nshow version|no-more\n")
        time.sleep(1)
        chan, rst_version = wait_end(chan)
        chan.send("\nshow system bank|no-more\n")
        time.sleep(1)
        chan, partition = wait_end(chan)
        ssh.close()
        print("%s: version info: -----> %s" % (threading.current_thread().name, rst_version))
        sys.stdout.flush()
        print("%s: ne partition: -----> %s" % (threading.current_thread().name, partition))
        sys.stdout.flush()
        if "Up-Partition" in partition:
            ne_partition = "up"
        else:
            ne_partition = "down"
        if re.findall(r"Ne Type.*NPT-1800.*2\+0", rst_version):
            ne_type = "1800_2p0"
            localfile = os.path.join(local_path, re.findall(r"NPT1800_Emb_2p0_\d+\.bin", ", ".join(os.listdir(local_path)))[0])
            remotefile = "/sdboot/" + ne_partition + "/NPT1800_Emb.bin"
        else:
            ne_type = re.findall(r"Ne Type.*NPT-(\w*)", rst_version)[0]
            localfile = os.path.join(local_path, re.findall("NPT"+ne_type+r"_Emb_\d+\.bin", ", ".join(os.listdir(local_path)))[0])
            remotefile = "/sdboot/" + ne_partition + "/NPT" + ne_type + "_Emb.bin"
    else:
        stdin, stdout, stderr = ssh.exec_command("cat /sdboot/startup")
        remotefile = re.findall(r"/.*\.bin", stdout.read().decode())[0]
        if "up" in remotefile:
            ne_partition = "up"
        else:
            ne_partition = "down"
        ne_type = re.findall(r"NPT(\w*)_", remotefile)[0]
        localfile = glob.glob(local_path+"\\"+remotefile.split("/")[-1].split(".")[0]+"_?????.bin")[0]

    print("%s: ne_type: -----> %s" % (threading.current_thread().name, ne_type))
    sys.stdout.flush()
    print("%s: localfile: -----> %s" % (threading.current_thread().name, localfile))
    sys.stdout.flush()
    print("%s: remotefile: -----> %s" % (threading.current_thread().name, remotefile))
    sys.stdout.flush()

    try:
        ssh.connect(ip, 22, username, password)
        print("%s: Save old version file..." % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("mv " + remotefile + " /sdboot/" + ne_partition + "/NPT.old")
    except Exception as e:
        print("%s: Save old file SSH connect failed." % threading.current_thread().name)
        sys.stdout.flush()
        raise
    
    ssh.close()

    sftp_transfer(ip, username, password, localfile, remotefile)
    try:
        ssh.connect(ip, 22, username, password)
        print("%s: start to sync at act mcp" % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("sync")
        print("%s: act mcp sync success: -----> %s" % (threading.current_thread().name, stdout.read().decode()))
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("sha256sum " + remotefile)
        checksum = stdout.read().decode()
        print("%s: sha256sum: -----> %s" % (threading.current_thread().name, checksum))
        sys.stdout.flush()
    except Exception as e:
        print("%s: Main sync SSH connect failed." % threading.current_thread().name)
        sys.stdout.flush()
        return -1
    if ne_type == "1800":
        shafile = localfile[:-9] + "1p1_sha256"
    else:
        shafile = localfile[:-9] + "sha256"
    f = open(shafile)
    sha_val = f.read()
    f.close()
    print("%s: local_sha256: -----> %s" % (threading.current_thread().name, sha_val))
    sys.stdout.flush()
    if sha_val in checksum:
        print("%s: checksum is OK" % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("rm -f /sdboot/" + ne_partition + "/NPT.old")
        print("%s: Clear backup file!" % threading.current_thread().name)
        ssh.close()
    else:
        print("%s: checksum is wrong" % threading.current_thread().name)
        sys.stdout.flush()
        stdin, stdout, stderr = ssh.exec_command("mv /sdboot/" + ne_partition + "/NPT.old " + remotefile)
        ssh.close()
        return
    
    if ne_type != "1800_2p0":
        print("%s: Check the standby card..." % threading.current_thread().name)
        ssh_stby(ip, username, password, ne_partition)

    try:
        ssh.connect(ip, 22, username, password)
    except Exception as e:
        print("%s: Reset SSH connect failed." % threading.current_thread().name)
        sys.stdout.flush()
        raise
    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999).decode()
    if username == "root" or username == "npti_sp":
        chan.send("lsh\n")
        chan, rst_lsh = wait_end(chan)
        # print(rst_lsh)
    if clear_cfg == "false":
        chan.send("\nrequest reset ne\n")
    else:
        chan.send("\nrequest reset no-recovery-sdh\n")
    reset_rst = ""
    while True:
        if re.findall(r"\(no\)", reset_rst[-15:]):
            # 执行复位操作
            chan.send("yes\n")
            time.sleep(1)
            break
        else:
            time.sleep(1)
            if chan.recv_ready():
                reset_rst += chan.recv(9999999).decode()
    time.sleep(1)
    if chan.recv_ready():
        reset_rst += chan.recv(9999).decode()
    print("%s: NE will reset: -----> %s" % (threading.current_thread().name, reset_rst))
    sys.stdout.flush()
    ssh.close()
    print("%s: thread finished." % threading.current_thread().name)
    sys.stdout.flush()

        
def sftp_thread(ip_list, version, clear_cfg, superuser):
    print("Thread %s is running..." % threading.current_thread().name)
    sys.stdout.flush()
    try:
        for ip in ip_list:
            locals()["t_"+ip] = threading.Thread(target=sftp_func, args=(ip, version, clear_cfg, superuser), name="Thread_" + ip)
            locals()["t_"+ip].start()
        for ip in ip_list:
            locals()["t_"+ip].join()
    except Exception as e:
        raise e
    finally:
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
    # version = sys.argv[1]
    # ip_list = sys.argv[2].replace(" ", "").split(",")
    # clear_cfg = sys.argv[3]
    # superuser = sys.argv[4]
    version = "7.5.614"
    ip_list = "200.200.121.51".replace(" ", "").split(",")
    clear_cfg = "false"
    superuser = "false"
    if not re.findall("Netstore-", version):
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
                print("The version is not found, please type again!")
                sys.exit()
        elif daily_cmcc:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI-CMCC\*", "NPT*" + "".join(daily_cmcc[0]) + ".bin")
            file_test = glob.glob(version_dir)
            if file_test:
                version_dir = os.path.dirname(file_test[0])
            else:
                print("The version is not found, please type again!")
                sys.exit()
        elif daily_date:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI", daily_date[0])
        elif daily_cmcc_date:
            version_dir = os.path.join(r"\\netstore-ch\R&D TN China\R&D_Server\Version Management\Dev_Version\DailyVersion\V7.5-NPTI-CMCC", "".join(daily_cmcc_date[0]))
        else:
            print("The version is not found, please type again!")
            sys.exit()
        # print(version_dir)
        version_dir = glob.glob(version_dir)
        if version_dir:
            if os.stat(version_dir[0]).st_ctime > os.stat(version_dir[-1]).st_ctime:
                    version_dir = version_dir[0]
            else:
                version_dir = version_dir[-1]
        else:
            print("The version is not found, please type again!")
            sys.exit()
    print("version path: " + version_dir)
    sys.stdout.flush()
    sftp_thread(ip_list, version_dir, clear_cfg, superuser)
