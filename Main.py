import psutil
import time
import os
import hashlib
from Process import Process
import multiprocessing

pro_file = open("processList.txt", "w")
pro_file.close()
log_file = open("Status_Log.txt", "w")
log_file.close()
log_file = open("data.txt", "w")
log_file.close()
process_list = {}
pre_avg = 5


def hash_file(_file):
    has = hashlib.md5()
    try:
        with open(_file, 'r+') as f:
            buf = f.read().encode('utf-8')
            has.update(buf)
        return has.hexdigest()
    except IOError:
        pass


hash_old_p = hash_file("processList.txt")
hash_old_s = hash_file("Status_Log.txt")


def test_hash_file():
    hash_new_p = hash_file("processList.txt")
    hash_new_s = hash_file("Status_Log.txt")
    global hash_old_p
    global hash_old_s
    if hash_old_p != hash_new_p:
        print('\n[WEANING]: processList file compromised! - file recycled\n')
        open('processList.txt', 'w').close()
        open('data.txt', 'w').close()
        print '>',
    if hash_old_s != hash_new_s:
        print('\n[WEANING]: Status_Log file compromised! - file recycled\n')
        open('Status_Log.txt', 'w').close()
        print '>',


def add_date(write=False):
    date = time.strftime("%d/%m/%Y")
    hour = time.strftime("%H:%M:%S")
    if write:
        with open("./data.txt", "a+") as file_date:
            file_date.write(date + " " + hour)
            file_date.write('\n')
    return "\n" + date + " " + hour + "\n"


def process_update():
    scan_ans = ""
    tmp = []
    scan_ans += (add_date(True))
    # psutil.process_iter() Return a generator yielding a Process instance for all running processes.
    for p in psutil.process_iter():
        try:
            if p.name() not in process_list:
                # process_list[name]=[current memory percent avg,max avg threshold ,num of scans of the pro]
                process_list[p.name()] = [p.memory_percent(), 0, 0]
            else:
                if process_list[p.name()][2] < pre_avg and process_list[p.name()][0] != "root":
                    process_list[p.name()][1] = max(process_list[p.name()][1], abs(p.memory_percent()
                                                                                   - process_list[p.name()][0]))
                    process_list[p.name()][2] += 1
                    process_list[p.name()][0] = (process_list[p.name()][0] +
                                                 p.memory_percent()) / (process_list[p.name()][2] + 1)
            scan_ans += ("name: " + p.name() + " pid: " + str(p.pid) + " ram: " + str(p.memory_percent()) + "\n")
            process = Process(p.name(), p.pid, str(p.memory_percent()))
        except psutil.AccessDenied:
            if p.name() not in process_list:
                scan_ans[p.name()] = ["root", 0, 0]
            scan_ans += ("name: " + p.name() + " pid: " + str(p.pid) + " ram: root" + "\n")
            process = Process(p.name(), p.pid, "root")
        try:
            for ch in p.children():
                child = ch.as_dict(attrs=["pid", "name", "cpu_percent", "memory_info"])
                process.add_child(Process(child["name"], child["pid"], child["memory_info"]))
        except psutil.NoSuchProcess:
            pass
        tmp.append(process)
    test_hash_file()
    with open("./processList.txt", "a") as processList:
        processList.write(scan_ans)
        processList.write("end")
    global hash_old_p
    hash_old_p = hash_file("processList.txt")
    return tmp


def compare_sam(sam_old, sam_new, first=True):
    ans = ""
    i = j = 0
    while i < len(sam_new) or j < len(sam_old):
        if i == len(sam_new):
            ans += ("[Alert - process died]: " + sam_old[j].get_name() + " " + str(sam_old[j].get_pid()) + "\n")
            j += 1
            continue
        if j == len(sam_old):
            ans += ("[Alert - new process]: " + sam_new[i].get_name() + " " + str(sam_new[i].get_pid()) + "\n")
            i += 1
            continue
        if str(sam_new[i].get_pid()) < str(sam_old[j].get_pid()):
            ans += ("[Alert - new process]: " + sam_new[i].get_name() + " " + str(sam_new[i].get_pid()) + "\n")
            i += 1
            continue
        if str(sam_new[i].get_pid()) > str(sam_old[j].get_pid()):
            ans += ("[Alert - process died]: " + sam_old[j].get_name() + " " + str(sam_old[j].get_pid()) + "\n")
            j += 1
            continue
        for process in sam_new[i].get_children():
            if not process.check(sam_old[j].get_children()):
                ans += ("[Alert - child process]: " + sam_new[i].get_name() + " " + str(sam_new[i].get_pid())
                        + " has new child: " + process.name + " " + str(process.get_pid()) + "\n")
        try:
            if process_list[sam_old[j].get_name()][2] == pre_avg and process_list[sam_old[j].get_name()][0] != "root" \
                    and sam_new[i].get_ram() != "root" and sam_old[j].get_ram() != "root":
                if abs(float(sam_new[i].get_ram()) - float(sam_old[j].get_ram())) > \
                        process_list[sam_new[i].get_name()][1]:
                    ans += ("[Alert - RAM]: " + sam_new[i].get_name() + " " + str(sam_new[i].get_pid())
                            + " cpu threshold has increased\n")
        except (KeyError, ValueError):
            pass
        i += 1
        j += 1
    if len(ans) != 0 and first:
        return add_date() + ans
    return ans


def scan(sam_old):
    sam_new = process_update()
    event = compare_sam(sam_old, sam_new)
    if event != "":
        test_hash_file()
        with open("./Status_Log.txt", "a") as o:
            o.write(event)
            print(event)
            print '>',
    global hash_old_s
    hash_old_s = hash_file("Status_Log.txt")
    old = sam_new
    return old


def get_samples(sam1, sam2):
    find = False
    sam_old = []
    sam_new = []
    with open("./processList.txt") as f:
        for i in f:
            line = i
            if sam1 in line or find:
                find = True
                if line.strip() == "end":
                    break
                n = line.find("name:")
                p = line.find("pid:")
                m = line.find("ram:")
                if n != -1 and p != -1 and m != -1:
                    name = line[n + 6:p - 1]
                    pid = line[p + 5:m - 1]
                    ram = line[m + 5:]
                    pro = Process(name, pid, ram)
                    sam_old.append(pro)
    find = False
    with open("./processList.txt") as f:
        for i in f:
            line = i
            if sam2 in line or find:
                find = True
                if line.strip() == "end":
                    break
                n = line.find("name:")
                p = line.find("pid:")
                m = line.find("ram:")
                if n != -1 and p != -1 and m != -1:
                    name = line[n + 6:p - 1]
                    pid = line[p + 5:m - 1]
                    ram = line[m + 5:]
                    pro = Process(name, pid, ram)
                    sam_new.append(pro)
    if len(sam_old) != 0 and len(sam_new) != 0:
        ans = compare_sam(sam_old, sam_new, False)
        if len(ans) == 0:
            ans = "[EMPTY]\n"
        s = "\n[Scan results]: " + sam1 + " - " + sam2 + "\n" + ans
        print (s + "[end]: " + sam1 + " - " + sam2)
    else:
        print ("\n[ERROR]: not enough data!\n")


def runner(sleep_time):
    cur = process_update()
    while True:
        time.sleep(sleep_time)
        cur = scan(cur)


def compare_samples():
    try:
        with open("./data.txt", "r+") as file_date:
            list_date = file_date.read().split("\n")
    except IOError:
        print ("[ERROR]: not enough data!\n")
        return
    if len(list_date) > 2:
        print ("\n--------------------------\n      manual mode\n"
               "--------------------------\nChoose two samples from the list:")
        for i in range(len(list_date) - 1):
            print (str(i + 1) + ") " + list_date[i])
        try:
            first_scan = raw_input("\nFirst sample:\n>")
            second_scan = raw_input("Second sample:\n>")
            if first_scan.isdigit() and second_scan.isdigit() and 0 < int(first_scan) < (len(list_date)) \
                    and 0 < int(second_scan) < (len(list_date)):
                get_samples(list_date[int(first_scan) - 1], list_date[int(second_scan) - 1])
            else:
                print ("\n[ERROR]: invalid input!\n")
        except (NameError, SyntaxError):
            print ("\n[ERROR]: invalid input!\n")
    else:
        print ("\n[ERROR]: not enough data!\n")


def view_files():
    user = raw_input("\n--------------------------\n          Files\n--------------------------\n"
                     "1) view processList\n2) view Status Log\n3) Back to main\n>")
    try:
        if user == '1':
            with open("./processList.txt", 'r') as f:
                ans = f.read()
                if len(ans) == 0:
                    ans = "[EMPTY]\n"
                print "\n[File start]: process List\n" + ans \
                    + "\n[File end]: process List\n"
            return
        if user == '2':
            with open("./Status_Log.txt", 'r') as f:
                ans = f.read()
                if len(ans) == 0:
                    ans = "[EMPTY]\n"
                print "\n[File start]: Status Log\n" + ans \
                  + "\n[File end]: Status Log\n"
            return
        if user == '3':
            return
    except IOError:
        print ("[ERROR]: not enough data!\n")
        return


def terminate_process():
    pid = raw_input("\n--------------------------\n    Terminate process"
                    "\n--------------------------\nEnter pid to terminate or Q to cancel:\n>")
    if pid == 'q' or pid == 'Q':
        return
    try:
        p = psutil.Process(int(pid))
        p.terminate()
        print("Process: " + pid + " terminated")
    except (psutil.NoSuchProcess, ValueError):
        print "[ERROR]: Not a valid pid!"


options = {'1': compare_samples,
           '2': view_files,
           '3': terminate_process,
           }


def main():
    if os.name == 'posix':
            if os.geteuid() != 0:
                print ("[ERROR]: Root privileges are required\nProgram Terminated!")
                return
    print("--------------------------")
    print("welcome to Process Monitor")
    print("--------------------------")
    sleep_time = 5
    scanner = multiprocessing.Process(target=runner, args=(int(sleep_time),))
    scanner.start()
    print("[Status]: Running...")
    user = raw_input("\n--------------------------\n          Main\n--------------------------\n"
                     "1) Compare samples\n2) View files\n3) Terminate process\n4) Settings\n5) Quit\n>")
    while user != '5':
        if user == '1' or user == "2" or user == "3":
            options[user]()
        if user == "4":
            print "\n--------------------------\n         Settings\n--------------------------" \
                  "\nScan is set to every {} sec!".format(sleep_time)
            sleep_time = raw_input("Enter how many sec until rescan:\n>")
            while not sleep_time.isdigit() or sleep_time < str(0):
                sleep_time = raw_input("[ERROR]: invalid input!\n>")
            print("\n[Status]: Resetting...")
            scanner.terminate()
            while scanner.is_alive():
                time.sleep(0.01)
            open('data.txt', 'w').close()
            scanner = multiprocessing.Process(target=runner, args=(int(sleep_time),))
            scanner.start()
            print "[Status]: Running..."
        user = raw_input("\n--------------------------\n          Main\n--------------------------\n"
                         "1) Compare samples\n2) View files\n3) Terminate process\n4) Settings\n5) Quit\n>")
    scanner.terminate()
    while scanner.is_alive():
        time.sleep(0.01)
    print ("\nProgram Terminated!")

if __name__ == '__main__':
    main()
