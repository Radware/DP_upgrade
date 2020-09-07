""" the script:
1. automatically save device configuration on local pc and compare after version upgraded
2. exports the devices MAC address + Firmware Version
3. accessing to radware portal for password generating
4. upgrading the device based on current version
5. verifying device is UP and running for next steps to take."""

# requests liabrary for API http requests
import requests
# time for managing time sleep between commands.
import time
# Json for parsing
import json
# using "islice" python function for slicing indexes.
from itertools import islice
# using for excel docs
import xlrd
# using selenium liabrary for managing web drivers - web pages automation.
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from pprint import pprint
# use socket for communication protocols for networking.
import socket
# FTP library for ftp access protocols.
import ftplib
import os
# library of AWS for managing AWS services and servers using API calls.
import boto3
from itertools import islice
import os

# function for check pings to particular host.
def Ping_Check(host):
    """
    Returns True if host responds to a ping request
    """
    import subprocess, platform

    # Ping parameters as function of OS and use number of "1" pings.
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1"
    args = "ping " + " " + ping_str + " " + host
    need_sh = False if  platform.system().lower()=="windows" else True

    # Ping
    return subprocess.call(args, shell=need_sh) == 0

# function for checking if some port to some IP is open and listening.
def isOpen(ip,port):
    CHECK_CON = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        CHECK_CON.connect((ip, int(port)))
        CHECK_CON.shutdown(2)
        return True
    except:
        return False

#function for connecting to Radware Portal and gennerate password using Selenium Library
def PORTAL_PASS(MAC,VER,RAD_USER,RAD_PASS,DP_PLATFORM):

    VER = VER[:4]
    print(VER)

    green = "\033[32m"
    # path to chrome driver
    PATH = "C:\Program Files (x86)\chromedriver.exe"
    # use Options function inside Selenium Library and hide the Chorme browser opening window
    options = Options()
    c_options = Options()
    c_options.add_argument('--headless')
    c_options.add_argument('--disable-gpu')

    # tell to selenium use chrome web driver type. (use web browser chrome and the web driver that located in path)
    driver = webdriver.Chrome(PATH, options=c_options)

    time.sleep(3)

    # tell to selenium use chromer web driver type. (use web browser chrome and the web driver that located in path)
    driver.get("https://login.radware.com/")
    window_before = driver.window_handles[0]

    time.sleep(3)
    # wait function to fully load the page
    WAIT = WebDriverWait(driver, 10)
    # username credentials to input inside the HTML form
    Login = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                       "/html[1]/body[1]/div[2]/div[1]/div[2]/div[1]/div[1]/form[1]/div[1]/div[2]/div[1]/div[2]/span[1]/input[1]")))
    time.sleep(1)
    # type the username in the typing box
    Login.send_keys(RAD_USER)
    # push the Return key for click on te botton
    Login.send_keys(Keys.RETURN)

    pswd = WAIT.until(EC.presence_of_element_located((By.ID,
                                                      "okta-signin-password")))
    pswd.send_keys(RAD_PASS)
    pswd.send_keys(Keys.RETURN)
    time.sleep(2)

    driver.get("https://portals.radware.com/Customer/Home/Tools/Password-Generator/")
    WAIT = WebDriverWait(driver, 10)
    # Enter the Product name - DefensePro
    PRODUCT = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                         "//select[@data-ng-model='ProductFamily']/option[text()='DefensePro']")))
    PRODUCT.click()
    # Enter the Product Platform  - DefensePro x4420
    if DP_PLATFORM == int(400):
        PLATFORM = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Platform']/option[text()='DefensePro 400']")))
        PLATFORM.click()
    elif DP_PLATFORM == int(200):
        PLATFORM = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Platform']/option[text()='DefensePro 200']")))
        PLATFORM.click()
    elif DP_PLATFORM == int(60):
        PLATFORM = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Platform']/option[text()='DefensePro 60']")))
        PLATFORM.click()
    elif DP_PLATFORM == int(20):
        PLATFORM = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Platform']/option[text()='DefensePro 20']")))
        PLATFORM.click()
    elif DP_PLATFORM == int(6):
        PLATFORM = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Platform']/option[text()='DefensePro 6']")))
        PLATFORM.click()
    # Enter the Version NUM  - 8.22.0.0
    if VER == "8.12":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.13.00']")))
        VERSION.click()
    if VER == "8.13":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.15.00']")))
        VERSION.click()
    if VER == "8.14":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.15.00']")))
        VERSION.click()
    if VER == "8.15":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.17.0.1']")))
        VERSION.click()
    elif VER == "8.16":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.17.0.1']")))
        VERSION.click()
    elif VER >= "8.17":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.22.0.0']")))
        VERSION.click()
    elif VER >= "8.17" and VER < "8.23":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "//select[@data-ng-model='Version']/option[text()='8.22.0.0']")))
        VERSION.click()
    elif VER >= "8.23":
        VERSION = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                             "//select[@data-ng-model='Version']/option[text()='8.23.0.0']")))
        VERSION.click()

    time.sleep(2)
    # enter on the link to copy the file size to text box.
    FILE_SIZE = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                           "/html[1]/body[1]/form[1]/div[4]/main[1]/div[1]/div[1]/div[3]/div[2]/div[1]/ul[1]/li[2]/a[1]")))
    FILE_SIZE.click()
    # enter the mac address of the DP device
    DEVICE_INFO = WAIT.until(EC.presence_of_element_located((By.ID, "address")))
    DEVICE_INFO.send_keys(MAC)
    # get te password for the DP to do software upgrade
    GET_PASS = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                          "/html[1]/body[1]/form[1]/div[4]/main[1]/div[1]/div[1]/div[3]/div[2]/div[1]/fieldset[1]/div[4]/button[1]")))
    GET_PASS.click()
    # find the password and print.
    PRINT_PASS = WAIT.until(EC.presence_of_element_located((By.XPATH,
                                                            "/html[1]/body[1]/form[1]/div[4]/main[1]/div[1]/div[1]/div[3]/div[2]/div[1]/div[3]/ol[1]/li[1]/div[1]/div[1]/span[1]")))
    return PRINT_PASS.text
    # print(PRINT_PASS.text)

    driver.close()

# function for Login to Apsolute vision and return Cookie.
def APSolute_Login(ip, u, p):
    try:
        while True:
            # change the request object to use as "session" - needed to procced with more API calls using same session
            session = requests.session()
            i = 'https://' + ip
            # login to APSolute vision
            login = {"username": u,
                     "password": p
                     }
            print(login)
            # convert as Json Dump
            CREDENTIALS = json.dumps(login)

            print(CREDENTIALS)
            API_LOGIN = '/mgmt/system/user/login'
            URL = i + API_LOGIN
            print(URL)
            # add HTTP Headers for API request
            headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
            # send the HTTP API request to the server including data and parameters.
            res = session.post(url=URL, headers=headers, data=CREDENTIALS, verify=False)
            print(res.content)
            # print('the status' + res.status_code)
            # verify login if ok save the cookie for use on next API calls.
            if res.text.find('error') != -1:
                return 'Login fail username or password incorrect'
                break
            else:
                session.get(i)
                c = session.cookies.values()
                COOKIE = c[0]
                return COOKIE
                print('Login succeed')
                break
    except:
        a = 'The APSolute_Login() function was not executed'
        print(a)
        with open('c:\dp_versions\log.txt', 'w') as f:
            f.write(a)

# function for downloading the configuration file and return the MAC+VERSION
def GETCONF(IP_VISION, RES, IP_DEV):
    app = []
    session = requests.session()

    API_CONF = 'https://' + IP_VISION + '/mgmt/device/byip/' + IP_DEV + '/config/getcfg'
    print(API_CONF)

    PARAMS = {"saveToDb": "false",
              "includePrivateKeys": "false"
              }
    Cookie = 'JSESSIONID=' + RES
    headers = {'Content-type': 'application/octet-stream', 'Accept': 'application/json',
               'cookie': Cookie}

    res = session.get(url=API_CONF, headers=headers, params=PARAMS, verify=False)
    head = res.headers
    print(head)
    head = res.status_code
    print(head)
    # print('configuration file downloaded')
    while res.status_code != 200:
        time.sleep(15)
        res = session.get(url=API_CONF, headers=headers, params=PARAMS, verify=False)
    else:
        print("upload file done")

    if not os.path.exists('C:\dp_versions\config_backup_dp_1.txt'):
        with open('C:\dp_versions\config_backup_dp_1.txt', 'wb') as f:
            f.write(res.content)
            with open("C:\dp_versions\config_backup_dp_1.txt") as f:
                for i in f:
                    if "DeviceDescription" in i:
                        for line in islice(f, 0, 1, 1):
                            app.append(line)
                            for i in app:
                                MAC = i[19:36]

                    if "Address" in i:
                        for line in islice(f, 0, 1):
                            app.append(line)
                            for i in app:
                                VERSION = i[19:27]
        # MAC = app[0]
        # VER = app[1]
        return app
        # print(MAC[19:27]+ " " + " " + VER[19:36])

    else:
        print("creating the new file for comparing config")
        missing = []
        with open('C:\dp_versions\config_backup_dp_2.txt', 'wb') as second_file:
            second_file.write(res.content)
        with open("C:\dp_versions\config_backup_dp_2.txt") as f:
            for i in f:
                if "DeviceDescription" in i:
                    for line in islice(f, 0, 1, 1):
                        app.append(line)
                        for i in app:
                            MAC = i[19:36]

                if "Address" in i:
                    for line in islice(f, 0, 1):
                        app.append(line)
                        for i in app:
                            VERSION = i[19:27]
        print("now comparing ")
        line_number = 0
        with open('C:\dp_versions\config_backup_dp_1.txt', 'r') as first_file:
            a_lines = first_file.readlines()
        with open('C:\dp_versions\config_backup_dp_2.txt', 'r') as second_file:
            b_lines = second_file.readlines()
            for line_a in islice(a_lines, 25, None):
                for line_b in islice(b_lines, 25, None):
                    if line_a in b_lines:
                        break
                    else:
                        line_number += 1
                        if line_a not in missing:
                            missing.append(line_a)
                            print(missing)
                            output = ''.join(missing)
                            with open('c:\dp_versions\missing_config_compare_old_to_new.txt', 'w') as c_file:
                                c_file.write(output)
                        else:
                            break

            print("Total Lines Missing :", len(missing))
        # MAC = app[0]
        # VER = app[1]
        return app
        # print(MAC[19:27]+ " " + " " + VER[19:36])



def FTP_SERVER(filename):
    print(filename)
    Local_Path = "C:/dp_versions/" + filename
    try:
        try:
            workbook = xlrd.open_workbook("C:\dp_versions\grade.xlsx")
            worksheet = workbook.sheet_by_name('Sheet1')
            print("opening excel file")
            time.sleep(3)
            params = []
            for i in range(worksheet.ncols):
                worksheet.cell_value(1, i)
                parameter = worksheet.cell_value(1, i)
                params.append(parameter)
            FTP_IP = params[8]
            FTP_USER = params[9]
            FTP_PASS = params[10]
        except IndexError as error:
            msg = str(error) + "\n" + "please fulfill the cells in the file or S3 AWS server was used"
            with open('c:\dp_versions\log4.txt', 'w') as f:
                f.write(msg)

        ftp = ftplib.FTP(FTP_IP, FTP_USER, FTP_PASS)
        print("File List:")
        ftp.dir()
        ftp.cwd("")

        with open('C:\\dp_versions\\' + filename, 'wb') as filess:
            print("pass files dictionary")

            ftp.retrbinary(f"RETR {filename}", filess.write)
            print("ok")
            file_s = ftp.size(filename)
            print(file_s)
            print("ok version has been downloaded")
        time.sleep(2)
        a = os.stat(r'C:\\dp_versions\\' + filename).st_size
        print(a)
        count = 0
        while file_s != a:
            print(count)
            count += 1
        else:
            print("file ready")
        files = [
            ('files', open(r'C:\\dp_versions\\' + filename, 'rb'))
        ]
        return files
    except:
        print("accessing AWS server")
        access_key = ''
        secret_key = ''
        print("open connection")
        S3_Connection = boto3.client('s3',
                region_name='eu-central-1',aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
        try:
            print("connection to AWS established")
            S3_Connection.download_file('defensepro-images', filename, Local_Path)
            print("Image " + filename + " downloaded")
            files = [
                ('files', open(r'C:\\dp_versions\\' + filename, 'rb'))
            ]
            return files
        except:
            a = "failed to download file from AWS s3 server"
            print(a)
            with open('c:\dp_versions\log6.txt', 'w') as f:
                f.write(a)

# function for all the arguments after the DP platform was recognized - this function activate all other finctions
# inside the Script - except the Software_upgrade function
def Final():
    try:
        workbook = xlrd.open_workbook("C:\dp_versions\grade.xlsx")
        worksheet = workbook.sheet_by_name('Sheet1')
        print("opening excel file")
        time.sleep(3)
        params = []
        for i in range(worksheet.ncols):
            worksheet.cell_value(1, i)
            parameter = worksheet.cell_value(1, i)
            params.append(parameter)

        IP_VISION = params[0]
        USERNAME = params[1]
        PASSWORD = params[2]
        ENTER_DP_IP = params[3]
        WANT_VER = params[4]
        RAD_USER = params[5]
        RAD_PASS = params[6]
        FTP_IP = params[7]
    except FileNotFoundError as error:
        with open('c:\dp_versions\log4.txt', 'w') as f:
            f.write(str(error), )
    except IndexError as error:
        msg = str(error) + "\n" + "please fulfill the cells in the file"
        with open('c:\dp_versions\log4.txt', 'w') as f:
            f.write(msg)

    # login validation

    while True:
        """IP_VISION = input("please enter IP address of the APSolute vision: ")
        USERNAME = input("please enter Username: ")
        PASSWORD = input("please enter password: ")"""

        RES = APSolute_Login(IP_VISION, USERNAME, PASSWORD)
        print(RES)
        time.sleep(1)
        if "fail" not in RES:
            try:
                DETAILS_OUT = GETCONF(IP_VISION, RES, ENTER_DP_IP)
                print(DETAILS_OUT)
                break
            except:
                a = 'The DETAILS_OUT() function was not executed , including the configuration file to export'
                print(a)
                with open('c:\dp_versions\log1.txt', 'w') as f:
                    f.write(a)
        if "fail" in RES:
            print("login failed - try again")
            # break

    MAC_OUT = DETAILS_OUT[0]
    print(MAC_OUT)
    VER_OUT = DETAILS_OUT[1]
    print("the Mac address is: " + MAC_OUT[19:36] + " " + " " + "and the corent software version is: " + VER_OUT[19:27])
    MAC_OUT = MAC_OUT[19:36]
    VER_OUT = VER_OUT[19:25]

    WANT_VER = str(WANT_VER)
    VER_OUT = VER_OUT
    green = "\033[32m"
    while VER_OUT != WANT_VER:
        print("the current version is : " + VER_OUT)
        print("the version you ask for is : " + WANT_VER)
        # accessing function in another file for password generation.
        try:
            PASSWORD_GEN = PORTAL_PASS(MAC_OUT, VER_OUT, RAD_USER,RAD_PASS,DP_PLATFORM)
            print(PASSWORD_GEN)
        except:
            Manually_password = input(
                green + "   please insert the password manually as no access to Radware's Portal from this App : ")
            PASSWORD_GEN = Manually_password
            print(PASSWORD_GEN)
            with open('c:\dp_versions\log2.txt', 'w') as f:
                f.write(PASSWORD_GEN + 'password generates manually or all function did not works')
        # function in another file for upgrading proccess.

        VER_UPGRADE = DP_Upgrade_soft(PASSWORD_GEN, VER_OUT, IP_VISION, ENTER_DP_IP, RES, WANT_VER)
        print(VER_UPGRADE)
        if "failed" in str(VER_UPGRADE):
            print(VER_UPGRADE)
            return "procces failed please try again and look at the logs file"
        else:
            # time to wait until device rebooted
            time.sleep(120)
            red = "\033[31m"
            white = "\033[37m"

            # code to check ping rechability to device.
            count = 1
            IP = ENTER_DP_IP
            RES_PING = Ping_Check(IP)
            while RES_PING == False:
                print(red + str(count) + ' times tried to reach the device')
                count = count + 1
                print(red + "please wait the DP still down")
                print(white)
                time.sleep(3)
                RES_PING = Ping_Check(IP)
                # ping(ip)
            else:
                print("\n""\n")
                print(green + "   congradulation the DP up again ")
                for RES_PING in range(4):
                    Ping_Check(IP)

            time.sleep(10)

            # try ssh to device - if ok go to next upgrade , if the upgraded version is the wanted version break.
            DP_ALIVE = isOpen(ENTER_DP_IP, '22')
            print("status of SSH connection ""\n")
            print(DP_ALIVE)

            while DP_ALIVE == False:
                time.sleep(10)
                DP_ALIVE = isOpen(ENTER_DP_IP, '22')
                print(red + "DP still not fully responding please wait, DP replay to ping but not to SSH/HTTPS")
                print(white)
            else:
                print("DP is up and running")
                time.sleep(60)
                DETAILS_OUT = GETCONF(IP_VISION, RES, ENTER_DP_IP)
                print(DETAILS_OUT)
                VER_OUT = DETAILS_OUT[1]
                VER_OUT = VER_OUT[19:25]
                print(VER_OUT)
    else:
        print("the current version is : " + VER_OUT)
        print("the version you ask for is : " + WANT_VER)
        print(green + "   Upgrade-Done successfully to version : " + WANT_VER)
        ENTER = input("please type any key for Exit")




try:
    workbook = xlrd.open_workbook("C:\dp_versions\grade.xlsx")
    worksheet = workbook.sheet_by_name('Sheet1')
    print("opening excel file for Platform")
    time.sleep(3)
    params = []
    for i in range(worksheet.ncols):
        worksheet.cell_value(1, i)
        parameter = worksheet.cell_value(1, i)
        params.append(parameter)

    DP_PLATFORM = params[7]
    print(DP_PLATFORM)

except FileNotFoundError as error:
    with open('c:\dp_versions\log4.txt','w') as f:
        f.write(str(error),)
except IndexError as error:
    msg = str(error) + "\n" + "please fulfill the cells in the file"
    with open('c:\dp_versions\log4.txt','w') as f:
        f.write(msg)

if DP_PLATFORM == int(400) or DP_PLATFORM == int(200):

    # function for upgrading the software after getting the password,cookie and devices IP.
    def DP_Upgrade_soft(PASSWORD,VERSION,IP_VISION,DP_IP,RES,WANT_VER):
        try:
            # use the Cookies from the Login Function
            Cookie = 'JSESSIONID='+ RES
            session = requests.session()
            # sending API resquest for locking the device
            head_lock = {'Content-type': 'application/json', 'Accept': 'application/json',
                        'cookie': Cookie}
            API_LOCK = 'https://' + IP_VISION + '/mgmt/system/config/tree/device/byip/' + DP_IP + '/lock'
            LOCK = session.post(url=API_LOCK, headers=head_lock, verify=False)
            l = LOCK.status_code
            if str(l) =='200':
                print("device has been locked")
            else:
                print(LOCK.status_code)
            # validate current version and the wanted version for upgrade process
            if VERSION >= "8.17.0":
                if WANT_VER >= "8.20.0" and WANT_VER < "8.21" or WANT_VER == "8.20":
                    print("need to download this version")
                elif WANT_VER >= "8.21.0" and WANT_VER < "8.22.0" and not WANT_VER == "8.22":
                    url = "https://"+IP_VISION+"/mgmt/device/byip/"+DP_IP+"/config/updatesoftware?softwareVersion=v8-21&&genpassauto=true&pass=" + PASSWORD
                    print(url)
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    # try to find the Image file Localy on PC
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-21-1-0-b39.tgz', 'rb'))
                        ]

                    # if file not found on PC use the File name and search it on the FTP function server.
                    except:
                        filename = "DefensePro_200-400_v8-21-1-0-b39.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    # after the file downloaded using the FTP function - take the File and send it together with the API request
                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))
                    time.sleep(5)

                    print(res.text)
                    return res.status_code

                elif WANT_VER >= "8.22.0" and WANT_VER < "8.23.0" or WANT_VER == "8.22":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-22&&genpassauto=true&pass=" + PASSWORD
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_200-400_v8-22-0-0-b107.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
                elif WANT_VER >= "8.23.0" or WANT_VER == "8.23":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-23&&genpassauto=true&pass=" + PASSWORD
                    print(url)

                    payload = []
                    #files = [
                    #   ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))   # still no version to upload
                    #]

                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }
                    print(headers)
                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
            elif VERSION < "8.17" and VERSION >= "8.13":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-17&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-17-0-1-b7.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_200-400_v8-17-0-1-b7.tgz"
                    files = FTP_SERVER(filename)
                    print(files)

                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

            elif VERSION < "8.15" and VERSION >= "8.12":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-15&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_200_DefensePro_400_v8-15-00-b116.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_200_DefensePro_400_v8-15-00-b116.tgz'"
                    files = FTP_SERVER(filename)
                    print(files)
                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

        except:
            a = 'problem in "DP_Upgrade_soft()" function  '
            print(a)
            with open('c:\dp_versions\log5.txt', 'w') as f:
                f.write(a)
                return ("Faild to upload version")


    UPGRADE_RESULT = Final()
    print(UPGRADE_RESULT)


if DP_PLATFORM == '60' or DP_PLATFORM == '20':

    def DP_Upgrade_soft(PASSWORD, VERSION, IP_VISION, DP_IP, RES, WANT_VER):
        try:
            Cookie = 'JSESSIONID=' + RES
            session = requests.session()

            head_lock = {'Content-type': 'application/json', 'Accept': 'application/json',
                         'cookie': Cookie}
            API_LOCK = 'https://' + IP_VISION + '/mgmt/system/config/tree/device/byip/' + DP_IP + '/lock'
            LOCK = session.post(url=API_LOCK, headers=head_lock, verify=False)
            l = LOCK.status_code
            if str(l) == '200':
                print("device has been locked")
            else:
                print(LOCK.status_code)

            if VERSION >= "8.17.0":
                if WANT_VER >= "8.20.0" and WANT_VER < "8.21" or WANT_VER == "8.20":
                    print("need to download this version")
                if WANT_VER >= "8.21.0" and WANT_VER < "8.22.0" and not WANT_VER == "8.22":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-21&&genpassauto=true&pass=" + PASSWORD
                    print(url)
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_20-60_v8-21-1-0-b39.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_20-60_v8-21-1-0-b39.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))
                    time.sleep(5)

                    print(res.text)
                    return res.status_code

                elif WANT_VER >= "8.22.0" and WANT_VER < "8.23.0" or WANT_VER == "8.22":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-22&&genpassauto=true&pass=" + PASSWORD
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_20-60_v8-22-0-0-b107.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_20-60_v8-22-0-0-b107.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
                elif WANT_VER >= "8.23.0" or WANT_VER == "8.23":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-23&&genpassauto=true&pass=" + PASSWORD
                    print(url)

                    payload = []
                    # files = [
                    #   ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))   # still no version to upload
                    # ]

                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }
                    print(headers)
                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
            elif VERSION < "8.17" and VERSION >= "8.13":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-17&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_20-60_v8-17-0-1-b7.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_20-60_v8-17-0-1-b7.tgz"
                    files = FTP_SERVER(filename)
                    print(files)

                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

            elif VERSION < "8.15" and VERSION >= "8.12":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-15&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_20_DefensePro_60_v8-15-00-b116.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_20_DefensePro_60_v8-15-00-b116.tgz"
                    files = FTP_SERVER(filename)
                    print(files)
                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

        except:
            a = 'problem in "DP_Upgrade_soft()" function  '
            print(a)
            with open('c:\dp_versions\log5.txt', 'w') as f:
                f.write(a)
                return ("Faild to upload version")

    UPGRADE_RESULT = Final()
    print(UPGRADE_RESULT)


if DP_PLATFORM == '6':

    def DP_Upgrade_soft(PASSWORD, VERSION, IP_VISION, DP_IP, RES, WANT_VER):
        try:

            Cookie = 'JSESSIONID=' + RES
            session = requests.session()

            head_lock = {'Content-type': 'application/json', 'Accept': 'application/json',
                         'cookie': Cookie}
            API_LOCK = 'https://' + IP_VISION + '/mgmt/system/config/tree/device/byip/' + DP_IP + '/lock'
            LOCK = session.post(url=API_LOCK, headers=head_lock, verify=False)
            l = LOCK.status_code
            if str(l) == '200':
                print("device has been locked")
            else:
                print(LOCK.status_code)

            if VERSION >= "8.17.0":
                if WANT_VER >= "8.20.0" and WANT_VER < "8.21" or WANT_VER == "8.20":
                    print("need to download this version")
                elif WANT_VER >= "8.21.0" and WANT_VER < "8.22.0" and not WANT_VER == "8.22":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-21&&genpassauto=true&pass=" + PASSWORD
                    print(url)
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_6_v8-21-1-0-b39.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_6_v8-21-1-0-b39.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))
                    time.sleep(5)

                    print(res.text)
                    return res.status_code

                elif WANT_VER >= "8.22.0" and WANT_VER < "8.23.0" or WANT_VER == "8.22":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-22&&genpassauto=true&pass=" + PASSWORD
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_6_v8-22-0-0-b107.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_6_v8-22-0-0-b107.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
                elif WANT_VER >= "8.23.0" or WANT_VER == "8.23":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-23&&genpassauto=true&pass=" + PASSWORD
                    print(url)

                    payload = []
                    # files = [
                    #   ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))   # still no version to upload
                    # ]

                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }
                    print(headers)
                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(5)

                    print(res.text)
                    return res.status_code
            elif VERSION < "8.17" and VERSION >= "8.13":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-17&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_6_v8-17-0-1-b7.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_6_v8-17-0-1-b7.tgz"
                    files = FTP_SERVER(filename)
                    print(files)

                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

            elif VERSION < "8.15" and VERSION >= "8.12":
                url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-15&&genpassauto=true&pass=" + PASSWORD
                headers = {
                    'Cookie': Cookie,
                    'Accept': 'application/json',
                }

                payload = []
                try:
                    files = [
                        ('files', open(r'C:\dp_versions\DefensePro_6_v8-15-00-b116.tgz', 'rb'))
                    ]

                except:
                    filename = "DefensePro_6_v8-15-00-b116.tgz"
                    files = FTP_SERVER(filename)
                    print(files)
                res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                print(res.text.encode('utf8'))

                time.sleep(15)

                print(res.text)
                return res.status_code

        except:
            a = 'problem in "DP_Upgrade_soft()" function  '
            print(a)
            with open('c:\dp_versions\log5.txt', 'w') as f:
                f.write(a)
                return ("Faild to upload version")

    UPGRADE_RESULT = Final()
    print(UPGRADE_RESULT)

else:
    DP_PLATFORM = str(DP_PLATFORM)
    DP_PLATFORM = DP_PLATFORM.upper()

    if DP_PLATFORM == "VM" or DP_PLATFORM == "VMWARE":
        def DP_Upgrade_soft(PASSWORD, VERSION, IP_VISION, DP_IP, RES, WANT_VER):
            try:

                Cookie = 'JSESSIONID=' + RES
                session = requests.session()

                head_lock = {'Content-type': 'application/json', 'Accept': 'application/json',
                             'cookie': Cookie}
                API_LOCK = 'https://' + IP_VISION + '/mgmt/system/config/tree/device/byip/' + DP_IP + '/lock'
                LOCK = session.post(url=API_LOCK, headers=head_lock, verify=False)
                l = LOCK.status_code
                if str(l) == '200':
                    print("device has been locked")
                else:
                    print(LOCK.status_code)

                if VERSION >= "8.17.0":
                    if WANT_VER >= "8.21.0" and WANT_VER < "8.22.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-21&&genpassauto=true&pass=" + PASSWORD
                        print(url)
                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }

                        payload = []
                        try:
                            files = [
                                ('files', open(r'C:\dp_versions\DefensePro_VA_v8-21-1-0-b39_Upgrade_VMware.tgz', 'rb'))
                            ]

                        except:
                            filename = "DefensePro_VA_v8-21-1-0-b39_Upgrade_VMware.tgz"
                            files = FTP_SERVER(filename)
                            print(files)

                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))
                        time.sleep(5)

                        print(res.text)
                        return res.status_code

                    elif WANT_VER >= "8.22.0" and WANT_VER < "8.23.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-22&&genpassauto=true&pass=" + PASSWORD
                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }

                        payload = []
                        try:
                            files = [
                                ('files', open(r'C:\dp_versions\DefensePro_VA_v8-22-0-0-b107_Upgrade_VMware.tgz', 'rb'))
                            ]

                        except:
                            filename = "DefensePro_VA_v8-22-0-0-b107_Upgrade_VMware.tgz"
                            files = FTP_SERVER(filename)
                            print(files)

                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))

                        time.sleep(5)

                        print(res.text)
                        return res.status_code
                    elif WANT_VER >= "8.23.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-23&&genpassauto=true&pass=" + PASSWORD
                        print(url)

                        payload = []
                        # files = [
                        #   ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))   # still no version to upload
                        # ]

                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }
                        print(headers)
                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))

                        time.sleep(5)

                        print(res.text)
                        return res.status_code
                elif VERSION < "8.17" and VERSION >= "8.13":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-17&&genpassauto=true&pass=" + PASSWORD
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_VA_8-17-0-1-b7_Upgrade_VMware.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_VA_8-17-0-1-b7_Upgrade_VMware.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(15)

                    print(res.text)
                    return res.status_code

            except:
                a = 'problem in "DP_Upgrade_soft()" function  '
                print(a)
                with open('c:\dp_versions\log5.txt', 'w') as f:
                    f.write(a)
                    return ("Faild to upload version")

        UPGRADE_RESULT = Final()
        print(UPGRADE_RESULT)

    elif DP_PLATFORM == "KVM":
        def DP_Upgrade_soft(PASSWORD, VERSION, IP_VISION, DP_IP, RES, WANT_VER):
            try:

                Cookie = 'JSESSIONID=' + RES
                session = requests.session()

                head_lock = {'Content-type': 'application/json', 'Accept': 'application/json',
                             'cookie': Cookie}
                API_LOCK = 'https://' + IP_VISION + '/mgmt/system/config/tree/device/byip/' + DP_IP + '/lock'
                LOCK = session.post(url=API_LOCK, headers=head_lock, verify=False)
                l = LOCK.status_code
                if str(l) == '200':
                    print("device has been locked")
                else:
                    print(LOCK.status_code)

                if VERSION >= "8.17.0":
                    if WANT_VER >= "8.21.0" and WANT_VER < "8.22.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-21&&genpassauto=true&pass=" + PASSWORD
                        print(url)
                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }

                        payload = []
                        try:
                            files = [
                                ('files', open(r'C:\dp_versions\DefensePro_VA_v8-21-1-0-b39_Upgrade_KVM.tgz', 'rb'))
                            ]

                        except:
                            filename = "DefensePro_VA_v8-21-1-0-b39_Upgrade_KVM.tgz"
                            files = FTP_SERVER(filename)
                            print(files)

                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))
                        time.sleep(5)

                        print(res.text)
                        return res.status_code

                    elif WANT_VER >= "8.22.0" and WANT_VER < "8.23.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-22&&genpassauto=true&pass=" + PASSWORD
                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }

                        payload = []
                        try:
                            files = [
                                ('files', open(r'C:\dp_versions\DefensePro_VA_8-17-0-1-b7_Upgrade_KVM.tgz', 'rb'))
                            ]

                        except:
                            filename = "DefensePro_VA_8-17-0-1-b7_Upgrade_KVM.tgz"
                            files = FTP_SERVER(filename)
                            print(files)

                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))

                        time.sleep(5)

                        print(res.text)
                        return res.status_code
                    elif WANT_VER >= "8.23.0":
                        url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-23&&genpassauto=true&pass=" + PASSWORD
                        print(url)

                        payload = []
                        # files = [
                        #   ('files', open(r'C:\dp_versions\DefensePro_200-400_v8-22-0-0-b107.tgz', 'rb'))   # still no version to upload
                        # ]

                        headers = {
                            'Cookie': Cookie,
                            'Accept': 'application/json',
                        }
                        print(headers)
                        res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                        print(res.text.encode('utf8'))

                        time.sleep(5)

                        print(res.text)
                        return res.status_code
                elif VERSION < "8.17" and VERSION >= "8.13":
                    url = "https://" + IP_VISION + "/mgmt/device/byip/" + DP_IP + "/config/updatesoftware?softwareVersion=v8-17&&genpassauto=true&pass=" + PASSWORD
                    headers = {
                        'Cookie': Cookie,
                        'Accept': 'application/json',
                    }

                    payload = []
                    try:
                        files = [
                            ('files', open(r'C:\dp_versions\DefensePro_VA_8-17-0-1-b7_Upgrade_KVM.tgz', 'rb'))
                        ]

                    except:
                        filename = "DefensePro_VA_8-17-0-1-b7_Upgrade_KVM.tgz"
                        files = FTP_SERVER(filename)
                        print(files)

                    res = session.request("POST", url, headers=headers, data=payload, files=files, verify=False)
                    print(res.text.encode('utf8'))

                    time.sleep(15)

                    print(res.text)
                    return res.status_code

            except:
                a = 'problem in "DP_Upgrade_soft()" function  '
                print(a)
                with open('c:\dp_versions\log5.txt', 'w') as f:
                    f.write(a)
                    return ("Faild to upload version")


        UPGRADE_RESULT = Final()
        print(UPGRADE_RESULT)
    else:
        print("you entered wrong DP platform please try again ")
