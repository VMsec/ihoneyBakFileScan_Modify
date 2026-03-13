# -*- coding: UTF-8 -*-
import requests
import logging
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from humanize import naturalsize
from tqdm import tqdm
from pathlib import Path
from typing import List, Optional, Dict, Set

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

ua = UserAgent()


def is_likely_backup_response(resp: requests.Response) -> bool:
    content_type = resp.headers.get('Content-Type', '').lower()
    forbidden = {'html', 'text', 'xml', 'json', 'javascript', 'image', 'css', 'font', 'audio', 'video'}
    return (
        resp.status_code == 200 and
        not any(t in content_type for t in forbidden) and
        ('application' in content_type or not content_type.strip())
    )


def check_url(url: str, session: requests.Session, timeout: int, proxies: Optional[Dict], output_path: Path) -> None:
    try:
        resp = session.get(
            url,
            headers={'User-Agent': ua.random},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=False,
            proxies=proxies
        )
        resp.raise_for_status()

        if not is_likely_backup_response(resp):
            return

        cl = resp.headers.get('Content-Length')
        if not cl or int(cl) <= 0:
            return

        size_str = naturalsize(int(cl), binary=True)
        logging.warning(f"[ success ] {url}  size: {size_str}")

        output_path.write_text(
            f"{url} size:{size_str}\n",
            encoding='utf-8',
            mode='a'
        )

    except requests.RequestException:
        pass
    except Exception as e:
        logging.debug(f"[err] {url} → {str(e)}")


def generate_candidates(base_url: str, prefixes: List[str], suffixes: List[str]) -> List[str]:
    parsed = urlparse(base_url)
    domain = parsed.netloc.lower().rstrip('.')
    parts = domain.split('.')

    if len(parts) < 2:
        return []

    variants: Set[str] = set([
        domain,
        ''.join(parts),
        '_'.join(parts),
        '.'.join(parts[1:]),
        parts[0],
        '_'.join(parts[1:]),
    ])

    if len(parts) > 2:
        without_tld = '.'.join(parts[:-1])
        variants.add(without_tld)
        variants.add(''.join(parts[:-1]))
        variants.add('_'.join(parts[:-1]))

    variants = {v for v in variants if v and len(v) > 1}

    candidates = []
    for prefix in variants:
        for suffix in suffixes:
            candidates.append(urljoin(base_url.rstrip('/') + '/', prefix + suffix))

    return sorted(set(candidates))


def scan_targets(targets: List[str], max_workers: int, timeout: int, proxies: Optional[Dict], output_path: Path):
    session = requests.Session()
    session.verify = False

    total_candidates = 0
    total_scanned = 0

    for idx, base_url in enumerate(targets, 1):
        candidates = generate_candidates(base_url, TMP_INFO_DIC, SUFFIX_FORMAT)
        site_count = len(candidates)
        total_candidates += site_count

        logging.info(f"[{idx}/{len(targets)}] {base_url} - Generated {site_count} candidates")

        if site_count == 0:
            continue

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            for url in candidates:
                futures.append(
                    executor.submit(check_url, url, session, timeout, proxies, output_path)
                )

            # 当前站点进度条（不留尾巴，避免刷屏）
            with tqdm(total=site_count, desc=f"Scanning {base_url}", unit="req", leave=False) as pbar:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception:
                        pass
                    pbar.update(1)
                    total_scanned += 1

        logging.info(f"[{idx}/{len(targets)}] {base_url} - Finished {site_count} candidates")

    logging.info(f"Scan completed | Total candidates: {total_candidates} | Scanned: {total_scanned}")


# ────────────────────────────────────────────────
# Dictionaries
# ────────────────────────────────────────────────

SUFFIX_FORMAT = [
    '.7z', '.backup', '.bak', '.bak.sql', '.bz2', '.db', '.dmp', '.dump',
    '.dump.sql', '.gz', '.jar', '.rar', '.sql', '.sql.bak', '.sql.gz',
    '.sqlite', '.sqlite3', '.tar', '.tar.bz2', '.tar.gz', '.tar.tgz',
    '.tar.xz', '.tbz', '.tbz2', '.tgz', '.txz', '.war', '.xz', '.zip'
]

# 77 items
tmp_info_dic = [
    '1', '127.0.0.1', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019',
    '2020', '2021', '2022', '2023', '2024', '2025', '2026', 'admin', 'archive', 'asp', 'aspx', 'auth', 'back',
    'backup', 'backups', 'bak', 'bbs', 'bin', 'clients', 'code', 'com', 'customers', 'dat', 'data',
    'database', 'db', 'dump', 'engine', 'error_log', 'faisunzip', 'files', 'forum', 'home', 'html',
    'index', 'joomla', 'js', 'jsp', 'local', 'localhost', 'master', 'media', 'members', 'my', 'mysql',
    'new', 'old', 'orders', 'php', 'sales', 'site', 'sql', 'store', 'tar', 'test', 'user', 'users',
    'vb', 'web', 'website', 'wordpress', 'wp', 'www', 'wwwroot', 'root', 'log'
]

# 130 items (commented out)
# tmp_info_dic = ['0','00','000','012','1','111','123','127.0.0.1','2','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','2026','234','3','333','4','444','5','555','6','666','7','777','8','888','9','999','a','about','admin','app','application','archive','asp','aspx','auth','b','back','backup','backups','bak','bbs','beifen','bin','cache','clients','code','com','config','core','customers','dat','data','database','db','download','dump','engine','error_log','extend','files','forum','ftp','home','html','img','include','index','install','joomla','js','jsp','local','login','localhost','master','media','members','my','mysql','new','old','orders','output','package','php','public','root','runtime','sales','server','shujuku','site','sjk','sql','store','tar','template','test','upload','user','users','vb','vendor','wangzhan','web','website','wordpress','wp','www','wwwroot','wz','log','数据库','数据库备份','网站','网站备份']

TMP_INFO_DIC = tmp_info_dic

INFO_DIC = list(set(prefix + suffix for prefix in TMP_INFO_DIC for suffix in SUFFIX_FORMAT))


# ────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────

if __name__ == '__main__':
    usageexample = '\n Example: python3 ihoneyBakFileScan_Modify.py -t 100 -f url.txt -o result.txt\n'
    usageexample += ' '
    usageexample += 'python3 ihoneyBakFileScan_Modify.py -u https://www.example.com/ -o result.txt'

    parser = ArgumentParser(
        add_help=True,
        usage=usageexample,
        description='A Website Backup File Leak Scan Tool.'
    )
    parser.add_argument('-f', '--url-file', dest="url_file", help="Example: url.txt")
    parser.add_argument('-t', '--thread', dest="max_threads", nargs='?', type=int, default=20, help="Max threads")
    parser.add_argument('-u', '--url', dest='url', nargs='?', type=str, help="Example: http://www.example.com/")
    parser.add_argument('-d', '--dict-file', dest='dict_file', nargs='?', help="Example: dict.txt")
    parser.add_argument('-o', '--output-file', dest="output_file", help="Example: result.txt")
    parser.add_argument('-p', '--proxy', dest="proxy", help="Example: socks5://127.0.0.1:1080 或 socks5h://user:pass@host:port")

    args = parser.parse_args()

    output_path = Path(args.output_file) if args.output_file else Path('result.txt')
    output_path.touch(exist_ok=True)

    proxies = None
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }

    targets = []
    if args.url:
        targets = [args.url.rstrip('/') + '/']
    elif args.url_file:
        try:
            with open(args.url_file, encoding='utf-8') as f:
                targets = [line.strip().rstrip('/') + '/' for line in f if line.strip()]
        except Exception as e:
            print(f"[ERROR] Cannot read file {args.url_file}: {e}")
            exit(1)
    else:
        parser.print_help()
        exit(1)

    if args.dict_file:
        try:
            with open(args.dict_file, encoding='utf-8') as f:
                custom = [line.strip() for line in f if line.strip()]
            INFO_DIC.extend(custom)
            INFO_DIC = list(set(INFO_DIC))
            logging.info(f"Appended {len(custom)} custom entries")
        except Exception as e:
            logging.warning(f"Failed to load custom dict: {e}")

    timeout = 12

    logging.info(f"Starting scan | Targets: {len(targets)} | Threads: {args.max_threads} | Output: {args.output_file or 'result.txt'}")
    if proxies:
        logging.info(f"Using proxy: {proxies.get('http', 'None')}")

    scan_targets(targets, args.max_threads, timeout, proxies, output_path)
    logging.info("Scan completed")
