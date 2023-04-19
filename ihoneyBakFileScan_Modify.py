# -*- coding: UTF-8 -*-

import requests
import logging
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime
from hurry.filesize import size
from fake_headers import Headers
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.WARNING, format="%(message)s")


def vlun(urltarget):
    try:
        if proxies:
            r = requests.get(url=urltarget, headers=header.generate(), timeout=timeout, allow_redirects=False, stream=True, verify=False, proxies=proxies)
        else:
            r = requests.get(url=urltarget, headers=header.generate(), timeout=timeout, allow_redirects=False, stream=True, verify=False)
        if (r.status_code == 200) & ('html' not in r.headers.get('Content-Type')) & (
                'image' not in r.headers.get('Content-Type')) & ('xml' not in r.headers.get('Content-Type')) & (
                'text' not in r.headers.get('Content-Type')) & ('json' not in r.headers.get('Content-Type')) & (
                'javascript' not in r.headers.get('Content-Type')):
            tmp_rarsize = int(r.headers.get('Content-Length'))
            rarsize = str(size(tmp_rarsize))
            if (int(rarsize[0:-1]) > 0):
                logging.warning('[ success ] {}  size:{}'.format(urltarget, rarsize))
                with open(outputfile, 'a') as f:
                    try:
                        f.write(str(urltarget) + '  ' + 'size:' + str(rarsize) + '\n')
                    except:
                        pass
            else:
                logging.warning('[ fail ] {}'.format(urltarget))
        else:
            logging.warning('[ fail ] {}'.format(urltarget))
    except Exception as e:
        logging.warning('[ fail ] {}'.format(urltarget))


def urlcheck(target=None, ulist=None):
    if target is not None and ulist is not None:
        if target.startswith('http://') or target.startswith('https://'):
            if target.endswith('/'):
                ulist.append(target)
            else:
                ulist.append(target + '/')
        else:
            line = 'http://' + target
            if line.endswith('/'):
                ulist.append(line)
            else:
                ulist.append(line + '/')
        return ulist


def dispatcher(url_file=None, url=None, max_thread=20, dic=None):
    urllist = []
    if url_file is not None and url is None:
        with open(str(url_file)) as f:
            while True:
                line = str(f.readline()).strip()
                if line:
                    urllist = urlcheck(line, urllist)
                else:
                    break
    elif url is not None and url_file is None:
        url = str(url.strip())
        urllist = urlcheck(url, urllist)
    else:
        pass

    with open(outputfile, 'a'):
        pass

    for u in urllist:
        check_urllist = []
        cport = None
        # ucp = u.strip('https://').strip('http://')
        if u.startswith('http://'):
            ucp = u.lstrip('http://')
        elif u.startswith('https://'):
            ucp = u.lstrip('https://')
        if '/' in ucp:
            ucp = ucp.split('/')[0]
        if ':' in ucp:
            cport = ucp.split(':')[1]
            ucp = ucp.split(':')[0]
            www1 = ucp.split('.')
        else:
            www1 = ucp.split('.')
        wwwlen = len(www1)
        wwwhost = ''
        for i in range(1, wwwlen):
            wwwhost += www1[i]

        current_info_dic = deepcopy(dic)  # deep copy
        suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                        '.gz', '.sql.gz', '.tar.tgz', '.backup']
        domainDic = [ucp, ucp.replace('.', ''), ucp.replace('.', '_'), wwwhost, ucp.split('.', 1)[-1],
                     (ucp.split('.', 1)[1]).replace('.', '_'), www1[0], www1[1]]

        for s in suffixFormat:
            for d in domainDic:
                current_info_dic.extend([d + s])

        for info in current_info_dic:
            url = str(u) + str(info)
            check_urllist.append(url)
            print("[add check] " + url)

        l = []
        p = ThreadPoolExecutor(max_thread)
        for url in check_urllist:
            obj = p.submit(vlun, url)
            l.append(obj)
        p.shutdown()


if __name__ == '__main__':
    usageexample = '\n       Example: python3 ihoneyBakFileScan_Modify.py -t 100 -f url.txt -o result.txt\n'
    usageexample += '                '
    usageexample += 'python3 ihoneyBakFileScan_Modify.py -u https://www.example.com/ -o result.txt'

    parser = ArgumentParser(add_help=True, usage=usageexample, description='A Website Backup File Leak Scan Tool.')
    parser.add_argument('-f', '--url-file', dest="url_file", help="Example: url.txt")
    parser.add_argument('-t', '--thread', dest="max_threads", nargs='?', type=int, default=1, help="Max threads")
    parser.add_argument('-u', '--url', dest='url', nargs='?', type=str, help="Example: http://www.example.com/")
    parser.add_argument('-d', '--dict-file', dest='dict_file', nargs='?', help="Example: dict.txt")
    parser.add_argument('-o', '--output-file', dest="output_file", help="Example: result.txt")
    parser.add_argument('-p', '--proxy', dest="proxy", help="Example: socks5://127.0.0.1:1080")

    args = parser.parse_args()
    # Use the program default dictionary, Accurate scanning mode, Automatic dictionary generation based on domain name.
    tmp_suffixFormat = ['.zip', '.rar', '.tar.gz', '.tgz', '.tar.bz2', '.tar', '.jar', '.war', '.7z', '.bak', '.sql',
                        '.gz', '.sql.gz', '.tar.tgz']
    # 77
    tmp_info_dic = ['1', '127.0.0.1', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019',
                    '2020', '2021', '2022', '2023', '2024', '2025', 'admin', 'archive', 'asp', 'aspx', 'auth', 'back',
                    'backup', 'backups', 'bak', 'bbs', 'bin', 'clients', 'code', 'com', 'customers', 'dat', 'data',
                    'database', 'db', 'dump', 'engine', 'error_log', 'faisunzip', 'files', 'forum', 'home', 'html',
                    'index', 'joomla', 'js', 'jsp', 'local', 'localhost', 'master', 'media', 'members', 'my', 'mysql',
                    'new', 'old', 'orders', 'php', 'sales', 'site', 'sql', 'store', 'tar', 'test', 'user', 'users',
                    'vb', 'web', 'website', 'wordpress', 'wp', 'www', 'wwwroot', 'root', 'log']
    # 130
    # tmp_info_dic = ['0','00','000','012','1','111','123','127.0.0.1','2','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','234','3','333','4','444','5','555','6','666','7','777','8','888','9','999','a','about','admin','app','application','archive','asp','aspx','auth','b','back','backup','backups','bak','bbs','beifen','bin','cache','clients','code','com','config','core','customers','dat','data','database','db','download','dump','engine','error_log','extend','files','forum','ftp','home','html','img','include','index','install','joomla','js','jsp','local','login','localhost','master','media','members','my','mysql','new','old','orders','output','package','php','public','root','runtime','sales','server','shujuku','site','sjk','sql','store','tar','template','test','upload','user','users','vb','vendor','wangzhan','web','website','wordpress','wp','www','wwwroot','wz','log','数据库','数据库备份','网站','网站备份']
    info_dic = []
    for a in tmp_info_dic:
        for b in tmp_suffixFormat:
            info_dic.extend([a + b])

    global outputfile
    if (args.output_file):
        outputfile = args.output_file
    else:
        outputfile = 'result.txt'
    #add proxy
    global proxies
    if (args.proxy):
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
    else:
        proxies = ''
    header = Headers(
        # generate any browser & os headeers
        headers=False  # don`t generate misc headers
    )

    timeout = 10

    try:
        if args.dict_file and outputfile:
            # Custom scan dictionary
            # This mode is not recommended for bulk scans. It is prone to false positives and can reduce program efficiency.
            custom_dict = list(set([i.replace("\n", "") for i in open(str(args.dict_file), "r").readlines()]))
            info_dic.extend(custom_dict)
        if args.url:
            dispatcher(url=args.url, max_thread=args.max_threads, dic=info_dic)
        elif args.url_file:
            dispatcher(url_file=args.url_file, max_thread=args.max_threads, dic=info_dic)
        else:
            print("[!] Please specify a URL or URL file name")
    except Exception as e:
        print(e)
