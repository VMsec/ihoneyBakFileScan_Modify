# -*- coding: UTF-8 -*-
import requests
import logging
import threading
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from humanize import naturalsize
from tqdm import tqdm
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from requests.adapters import HTTPAdapter

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

ua = UserAgent()
OUTPUT_LOCK = threading.Lock()


def is_likely_backup_response(resp: requests.Response) -> bool:
    content_type = resp.headers.get('Content-Type', '').lower()
    forbidden = {'html', 'text', 'xml', 'json', 'javascript', 'image', 'css', 'font', 'audio', 'video'}
    return (
        resp.status_code == 200 and
        not any(t in content_type for t in forbidden) and
        ('application' in content_type or not content_type.strip())
    )


def is_site_accessible(
    url: str,
    session: requests.Session,
    timeout: int,
    proxies: Optional[Dict]
) -> Tuple[bool, str]:
    """Only skip when the target is unreachable at the network layer."""
    try:
        session.get(
            url,
            headers={'User-Agent': ua.random},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            proxies=proxies
        )
        return True, "http_response_received"
    except requests.exceptions.SSLError as exc:
        return False, f"ssl_error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        return False, f"connection_error: {exc}"
    except requests.exceptions.Timeout as exc:
        return False, f"timeout: {exc}"
    except requests.RequestException as exc:
        return False, f"request_error: {exc}"


def check_url(url: str, session: requests.Session, timeout: int, proxies: Optional[Dict], output_path: Path) -> None:
    try:
        with session.get(
            url,
            headers={'User-Agent': ua.random},
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=False,
            proxies=proxies
        ) as resp:
            if not is_likely_backup_response(resp):
                return

            cl = resp.headers.get('Content-Length')
            if not cl or int(cl) <= 0:
                return

            size_str = naturalsize(int(cl), binary=True)
            logging.warning(f"[ success ] {url}  size: {size_str}")

            with OUTPUT_LOCK:
                with open(output_path, 'a', encoding='utf-8') as f:
                    f.write(f"{url} size:{size_str}\n")

    except requests.RequestException:
        pass
    except Exception as e:
        logging.debug(f"[err] {url} → {str(e)}")


def generate_candidates(base_url: str, prefixes: List[str], suffixes: List[str]) -> List[str]:
    parsed = urlparse(base_url)
    domain = parsed.netloc.lower().rstrip('.')
    parts = domain.split('.')

    variants: Set[str] = set()

    # 特殊处理纯 IPv4 地址（如 192.168.2.111）
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        variants.add(domain)                   # 192.168.2.111
        variants.add(''.join(parts))           # 1921682111
        variants.add('_'.join(parts))          # 192_168_2_111
    else:
        # 正常域名逻辑
        if len(parts) >= 1:
            variants.add(domain)
            variants.add(parts[0])
            variants.add(''.join(parts))
            if len(parts) > 1:
                variants.add('.'.join(parts[1:]))
                variants.add('_'.join(parts[1:]))

        if len(parts) > 2:
            without_tld = '.'.join(parts[:-1])
            variants.add(without_tld)
            variants.add(''.join(parts[:-1]))
            variants.add('_'.join(parts[:-1]))

    # Merge variants with the dictionary prefixes (like 'back', 'www')
    final_prefixes = variants.union(set(prefixes))
    final_prefixes = {v for v in final_prefixes if v and len(str(v)) > 0}

    candidates = []
    base_path = base_url.rstrip('/') + '/'
    for p in final_prefixes:
        for suffix in suffixes:
            filename = f"{p}{suffix}" if suffix.startswith('.') else f"{p}.{suffix}"
            candidates.append(urljoin(base_path, filename))

    return sorted(set(candidates))


def scan_targets(
    targets: List[str],
    max_workers: int,
    timeout: int,
    proxies: Optional[Dict],
    output_path: Path,
    prefixes: List[str]
) -> None:
    session = requests.Session()
    session.verify = False

    pool_size = max(50, max_workers)
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=2)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    total_candidates = 0
    total_scanned = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for idx, base_url in enumerate(targets, 1):
            logging.info(f"[{idx}/{len(targets)}] Checking connectivity for {base_url}...")
            accessible, reason = is_site_accessible(base_url, session, timeout, proxies)
            if not accessible:
                logging.error(f"[{idx}/{len(targets)}] {base_url} is unreachable ({reason}). Skipping...")
                continue

            candidates = generate_candidates(base_url, prefixes, SUFFIX_FORMAT)
            site_count = len(candidates)
            total_candidates += site_count

            logging.info(f"[{idx}/{len(targets)}] {base_url} - Generated {site_count} candidates")

            if site_count == 0:
                logging.warning(f"[{idx}/{len(targets)}] {base_url} - No candidates generated (可能为无效域名/IP)")
                continue

            with tqdm(total=site_count, desc=f"Scanning {base_url}", unit="req", leave=False) as pbar:
                for _ in executor.map(
                    lambda candidate: check_url(candidate, session, timeout, proxies, output_path),
                    candidates
                ):
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

TMP_INFO_DIC = list(dict.fromkeys(tmp_info_dic))


def normalize_targets(raw_targets: List[str]) -> List[str]:
    normalized: List[str] = []
    seen: Set[str] = set()

    for target in raw_targets:
        value = target.strip()
        if not value:
            continue

        normalized_value = value.rstrip('/') + '/'
        if normalized_value in seen:
            continue

        seen.add(normalized_value)
        normalized.append(normalized_value)

    return normalized


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
    parser.add_argument('-u', '--url', dest='url', nargs='?', type=str, help="Example: http://www.example.com/ or http://192.168.1.1")
    parser.add_argument('-d', '--dict-file', dest='dict_file', nargs='?', help="Example: dict.txt")
    parser.add_argument('-o', '--output-file', dest="output_file", help="Example: result.txt")
    parser.add_argument('-p', '--proxy', dest="proxy", help="Example: socks5://127.0.0.1:1080 or socks5://user:pass@host:port")

    args = parser.parse_args()

    if args.max_threads < 1:
        parser.error("--thread must be greater than 0")

    output_path = Path(args.output_file) if args.output_file else Path('result.txt')
    # Ensure file exists
    output_path.touch(exist_ok=True)

    proxies = None
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }

    targets: List[str] = []
    if args.url:
        targets = normalize_targets([args.url])
    elif args.url_file:
        try:
            with open(args.url_file, encoding='utf-8') as f:
                targets = normalize_targets(f.readlines())
        except Exception as e:
            print(f"[ERROR] Cannot read file {args.url_file}: {e}")
            exit(1)
    else:
        parser.print_help()
        exit(1)

    active_prefixes = list(TMP_INFO_DIC)
    if args.dict_file:
        try:
            with open(args.dict_file, encoding='utf-8') as f:
                custom = [line.strip() for line in f if line.strip()]
            active_prefixes = list(dict.fromkeys(active_prefixes + custom))
            logging.info(f"Appended {len(custom)} custom prefix entries")
        except Exception as e:
            logging.warning(f"Failed to load custom dict: {e}")

    # Set timeout to 15 seconds
    timeout = 15

    logging.info(f"Starting scan | Targets: {len(targets)} | Threads: {args.max_threads} | Output: {output_path}")
    if proxies:
        logging.info(f"Using proxy: {proxies.get('http', 'None')}")

    scan_targets(targets, args.max_threads, timeout, proxies, output_path, active_prefixes)
    logging.info("Scan completed")
