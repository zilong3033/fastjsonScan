##!/usr/bin/env python
# coding:utf-8
# Author:SToNe

# 目前减少文件生成,加入线程池，由于IO等待，加入协程，提高大c段扫描，后面可加入SYN等扫描提高效率，使用scapy库。
#需下载requests和gevent库

import gevent,socket
from gevent import monkey
monkey.patch_all()   #打补丁，使所有IO延迟异步

import threading
import queue
import sys, time, re,traceback,subprocess,os
import requests
import chardet
import optparse
from concurrent.futures import ThreadPoolExecutor, wait
from requests.packages.urllib3.exceptions import InsecureRequestWarning

socket.setdefaulttimeout(5)   #全局socket的timeout为5s


# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
lock = threading.Lock()

count=[]

webports = "80,443,8080,81,82,83,84,85,88,8000,8010,8050,808,8880,8888,8443,8081,8161,8090,9443,7002,7001,8088,18080,18088,8082,8083,18443,9090,9080,6443,7443,8001,8002,9000,9001,8082"

webports="80,81,82,83,84,85,86,88,89,98,443,1080,1099,1443,1471,1494,1503,1505,1515,1521,1554,1588,1610,1720,1723,1741,1777,1830,1863,1880,1883,1901,1911,1935,1947,1962,1967,1991,5001,5002,5004,5005,7000,7001,7002,7003,7443,7780,7788,7911,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8020,8025,8030,8040,8058,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8111,8112,8118,8123,8125,8126,8129,8138,8139,8140,8159,8161,8181,8182,8194,8291,8443,8480,8500,8529,8545,8546,8554,8649,8686,8765,8800,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8889,8890,8899,8983,8999,9000,9001,9002,9003,9009,9010,9030,9042,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9292,9295,9300,9306,9333,9334,9418,9443,9444,9446,9527,9530,9595,9653,9668,9700,9711,9801,9864,9869,9870,9876,9943,9944,9981,10000,10001,10003,10005,10030,10035,10162,10243,10250,10255,10332,10333,10443,10554,11001,11211,11300,11310,11371,11965,12000,12300,12345,12999,13579,13666,13720,13722,14000,14147,14265,14443,14534,15000,16000,16010,16030,16443,16922,16923,16992,16993,17000,17443,17988,18000,18001,18080,18081,18086,18245,18246,18264,18443,19150,19888,19999,20000,20332,20547,20880,22105,22335,23023,23424,25000,25010,25105,25565,26214,26470,27015,27016,27017,28017,28080"

def check_url(ip, port):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:47.0) Gecko/20100101 Firefox/47.0'}
    if port in (443,8443,6443,7443,9443,18443,8443,1443,17443,18443):
        url = "https://" + ip + ":" + str(port)
    else:
        url = "http://" + ip + ":" + str(port)
    try:
        title = title1 = None
        with requests.get(url, headers=headers, allow_redirects=False, verify=False, timeout=TIMEOUT) as r:
            r_detectencode = chardet.detect(r.content)
            actual_encode = r_detectencode['encoding']
            if r.content:
                title = re.search('<title>(.*?)</title>', r.content.decode(actual_encode), re.S | re.I)
            if title:
                title = title.groups()[0].replace('\r\n', '').replace('\n', '')
            else:
                title = "None"
            banner = ""
            try:
                banner += r.headers['server']
            except:
                pass
            code = r.status_code
        # print code
        if code == 301 or code == 302:
            with requests.get(url, headers=headers, verify=False, timeout=TIMEOUT) as s:
                s_detectencode = chardet.detect(s.content)
                actual_encode = s_detectencode['encoding']
                contents=s.content
            try:
                if contents:
                    title1 = re.search('<title>(.*?)</title>', contents.decode(actual_encode), re.S | re.I)
                if title1:
                    title1 = title1.groups()[0].replace('\r\n', '').replace('\n', '')
                else:
                    title1 = None
                lock.acquire()
                try:
                    print("%-30s %-6s %-20s %-30s " % (url, code, banner, title1))
                    f = open(fw, 'a').write("%-30s %-6s %-20s %-30s %30s \n" % (url, code, banner, title1, str(s.url)))
                    open(fu,'a').write(url+"\n")
                finally:
                    lock.release()
                    # add_web(url,code,banner,title1)
            except Exception as e:
                # traceback.print_exc()
                lock.acquire()
                try:
                    f = open(fw, 'a').write("%-30s %-6s %-20s %-30s %30s \n" % (url, code, banner, title1, str(s.url)))
                    open(fu, 'a').write(url + "\n")
                finally:
                    lock.release()
                    # add_web(url,code,banner,title)

        else:
            lock.acquire()
            try:
                print("%-30s %-6s %-20s %-30s " % (url, code, banner, title))
                f = open(fw, 'a').write("%-30s %-6s %-20s %-30s \n" % (url, code, banner, title))
                open(fu, 'a').write(url + "\n")
            finally:
                lock.release()
                # add_web(url,code,banner,title)
    except Exception as e:
        #traceback.print_exc()
        if re.search("SSL", str(e)):
            lock.acquire()
            try:
                f = open(fw, 'a').write("%-30s \n" % (url))
                open(fu,'a').write(url+"\n")
            finally:
                lock.release()
        else:
            lock.acquire()
            try:
                # print  "%s:%s open but not http : Error Code %s" %(ip,port,e)
                print("%s:%s open" % (ip, port))
            finally:
                lock.release()


def socket_port(ip, port):
    """
    输入IP和端口号，扫描判断端口是否开放
    """
    # pre_ip = re.compile('(\d+\.\d+)\.(\d+\.)(\d+)').search(sys.argv[1]).group(1)
    try:
        s=socket.socket()
        result=s.connect_ex((ip,port))
        s.close()
        if result == 0:
            if str(port) not in webports.split(","):
                    print("%s:%s open " % (ip, port))
            else:
                check_url(ip, port)
                pass
        else:
            if result != 10061 and result != 10060:
                if result == 10065:
                    print("未连接网络异常或本地网络异常！")
                    sys.exit(0)
                else:
                    if result == 113 or result == 111 or result == 110:
                        pass
                    else:
                        pass
                        # print(result)
    except Exception as e:
        traceback.print_exc()
        pass
    finally:
        pass

class scan():
    def __init__(self, ipl, port):
        self.threads_num = 256
        self.ipl = ipl
        self.port = port
        self.IPs = queue.Queue()
        for i in self.ipl:
            self.IPs.put([i, port])

    def scan_s(self):
        threads = []
        while self.IPs.qsize() > 0:
            iport = self.IPs.get()
            # print iport
            # print url
            try:
                socket_port(iport[0], iport[1])
            except Exception as e:
                traceback.print_exc()
                pass

    def run(self):
        try:
            threads = []
            self.scan_s()
        except RuntimeError as e:
            traceback.print_exc()
            #print("由于系统线程数上限，无法创建新线程！")
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception:
            traceback.print_exc()
            pass
        finally:
            pass
        # exit()


def cScan(pre_ip, ports):
    print("[+]Checking %s ip ..." % (len(pre_ip)))
    li=[]
    for port in ports:
        s = scan(ipl=pre_ip, port=int(port))
        li.append(gevent.spawn(s.run))
    gevent.joinall(li)
    print("ips %s is over in %.2f seconds!" % (len(pre_ip), time.time() - start_t))
    sys.exit(0)


def xray_webscan():
    xray_path="D:\\Program Files\\xray\\xray_windows_386.exe"
    url_file=fu
    xray_output="xray-"+str(datetime.datetime.now().strftime('%m%d%H'))+".html"
    xray_cmd=xray_path+" webscan --url-file "+url_file+" --html-output "+xray_output
    res=subprocess.Popen(args=xray_cmd,stderr=subprocess.STDOUT,stdout=subprocess.PIPE,stdin=subprocess.PIPE)
    while True:
        line = res.stdout.readline()
        line = line.rstrip().decode('utf8')
        print(line)
        if (line == '' and res.poll() != None):
            break


if __name__ == '__main__':
    parser = optparse.OptionParser(
        'usage: %prog [options] target\nexample:\n\t %prog ip.txt\n\t%prog -i 192.168.1.1', version="%prog 1.0.9.10",
        description="default scan HttpTitle")
    parser.add_option('-i', '--ips', dest='ips', type='string', help='192.168.1.1,192.168.2.1')
    parser.add_option('-x','--xray',dest='xray',type='string',help='use need add xray path')
    parser.add_option('-m','--mode',dest='mode',type='string',help='e为企业级web端口，d为默认web端口，s为精简web端口')
    parser.add_option('--timeout', dest='timeout', default=5, type=int, help='Num of timeout ,5 by default')
    parser.add_option('-t', '--threads', dest='threads', default=3, type=int, help='Num of scan threads, 3 by default')
    parser.add_option('-p', '--ports', dest='ports',
                      default="80,443,8080,81,82,83,84,85,88,8000,8010,8050,808,8880,8888,8443,8081,8161,8090,9443,7002,7001,8088,18080,18088,8082,8083,18443,9090,9080,6443,7443,8001,8002,9000,9001,8082",
                      type='string',
                      help='the ports you want to scan,default ports (80,443,8080,81,82,88,8000,8010,8050,808,8880,8888,8443,8081,8161,8090,9443,7002,7001,8088,18080,18088,8082,8083,18443)')
    parser.add_option('-o', '--output', dest="outfile", default="result.txt", help="default output result.txt")

    if sys.platform=="linux":
        #由于linux打开文件数默认1024，修改大点，有利于并发，这里不生效需要手动改
        os.system("ulimit -n 10240")

    # 解析参数
    (options, args) = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(0)
    start_t = time.time()
    fw = options.outfile+str(datetime.datetime.now().strftime('%m%d%H'))+".txt"
    fu="urls-"+str(datetime.datetime.now().strftime('%m%d%H'))+".txt"
    THREADS_NUM = options.threads
    TIMEOUT = options.timeout
    if options.ips:
        l1 = []
        ips = options.ips
        if str(ips).find(",") != -1:
            ip_list = ips.split(",")
            for i in ip_list:
                l1.append(i.strip())
            print(l1)
        else:
            l1.append(options.ips.strip())
    else:
        f = open(sys.argv[1], 'r').readlines()
        l1 = []
        for i in f:
            l1.append(i.strip())
    l2 = list(set(l1))
    print(len(l2))

    #端口处理
    ports = options.ports
    #e为企业级web端口，d为默认web端口，s为精简web端口
    if options.mode=="s":
        ports="80,443,8080,81,82,83,84,85,88,8000,8010,8050,808,8880,8888,8443,8081,8161,8090,9443,7002,7001,8088,18080,18088,8082,8083,18443,9090,9080,6443,7443,8001,8002,9000,9001,8082"
    if options.mode=="d":
        ports="80,81,82,83,84,85,86,88,89,98,443,1080,1099,1443,1471,1494,1503,1505,1515,1521,1554,1588,1610,1720,1723,1741,1777,1830,1863,1880,1883,1901,1911,1935,1947,1962,1967,1991,5001,5002,5004,5005,7000,7001,7002,7003,7443,7780,7788,7911,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8020,8025,8030,8040,8058,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8111,8112,8118,8123,8125,8126,8129,8138,8139,8140,8159,8161,8181,8182,8194,8291,8443,8480,8500,8529,8545,8546,8554,8649,8686,8765,8800,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8889,8890,8899,8983,8999,9000,9001,9002,9003,9009,9010,9030,9042,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9292,9295,9300,9306,9333,9334,9418,9443,9444,9446,9527,9530,9595,9653,9668,9700,9711,9801,9864,9869,9870,9876,9943,9944,9981,10000,10001,10003,10005,10030,10035,10162,10243,10250,10255,10332,10333,10443,10554,11001,11211,11300,11310,11371,11965,12000,12300,12345,12999,13579,13666,13720,13722,14000,14147,14265,14443,14534,15000,16000,16010,16030,16443,16922,16923,16992,16993,17000,17443,17988,18000,18001,18080,18081,18086,18245,18246,18264,18443,19150,19888,19999,20000,20332,20547,20880,22105,22335,23023,23424,25000,25010,25105,25565,26214,26470,27015,27016,27017,28017,28080"
    if options.mode=="e":
        pass
        #ports="80-100,443,1000-2000,5001-5010,10000,10001,10003,10005,10030,10035,10162,10243,10250,10255,10332,10333,10443,10554,11001,11211,11300,11310,11371,11965,12000,12300,12345,12999,13579,13666,13720,13722,14000,14147,14265,14443,14534,15000,16000,16010,16030,16443,16922,16923,16992,16993,17000,17443,17988,18000,18001,18080,18081,18086,18245,18246,18264,18443,19150,19888,19999,20000,20332,20547,20880,22105,22335,23023,23424,25000,25010,25105,25565,26214,26470,27015,27016,27017,28017,28080"
    
    if "-" in ports:
        portl=[]
        ports = ports.split('-')
        for port in range(int(ports[0]), int(ports[1]) + 1):
            portl.append(port)
        ports=portl
    else:
        ports = ports.split(',')

    #ports大于25小于100，一次26个c段
    #ports大于100小于1000，一次3个c段
    #ports大于1000，需要处理端口，一次1个主机
    n=1
    if len(ports)<50:
        n=26
    else:
        if len(ports)<101:
            n=20
        elif len(ports)<250:
            n=8
        elif len(ports)<1000:
            n=1
        else:
            print("大于1000端口，未优化，由于操作系统并发限制。")
            #exit()

    # 加入线程池，每次扫描
    threadPoolList = []
    
    num=255*n
    ta=[l2[i:i+255] for i in range(0,len(l2),255)]
    tasks=[ta[i:i+n] for i in range(0,len(ta),n)]  #每num个一个task
    #print(tasks)
    THREADS_NUM = n  #一次n个线程

    t=1  #任务计数器
    for task in tasks:
        pool = ThreadPoolExecutor(max_workers=THREADS_NUM)
        try:
            for i in task:
                threadPoolList.append(pool.submit(cScan, i, ports))

            wait(threadPoolList)
        except KeyboardInterrupt:
            pool.shutdown(wait=False)
            exit()
        print("task "+ str(t) +" is over in %.2f seconds!" % (time.time()-start_t))
        t = t + 1

    print("It is over in %.2f seconds" % (time.time() - start_t))
    if options.xray:
        print("start xray webscan...")
        xray_webscan()

