# -*- coding: UTF-8 -*-
import requests
import logging
import threading
import uuid
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import closing
from urllib.parse import urljoin, urlparse
from fake_useragent import UserAgent
from humanize import naturalsize
from tqdm import tqdm
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple
from requests.adapters import HTTPAdapter

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

ua = UserAgent()
OUTPUT_LOCK = threading.Lock()


def build_session(max_workers: int) -> requests.Session:
    session = requests.Session()
    session.verify = False

    pool_size = max(50, max_workers)
    # Disable retries for large-scale scans to avoid timeout amplification.
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def make_headers() -> Dict[str, str]:
    return {
        'User-Agent': ua.random,
        'Accept-Encoding': 'identity'
    }


def make_range_headers() -> Dict[str, str]:
    headers = make_headers()
    headers['Range'] = 'bytes=0-63'
    return headers


def normalize_header_value(value: str) -> str:
    return value.strip().lower()


def get_candidate_suffix(url: str) -> str:
    path = urlparse(url).path.lower()
    for suffix in sorted(SUFFIX_FORMAT, key=len, reverse=True):
        if path.endswith(suffix):
            return suffix
    return ''


def has_download_disposition(resp: requests.Response) -> bool:
    content_disposition = resp.headers.get('Content-Disposition', '').lower()
    return 'attachment' in content_disposition or 'filename=' in content_disposition


def is_probably_redirect_trap(resp: requests.Response) -> bool:
    if resp.status_code not in {301, 302, 303, 307, 308}:
        return False

    location = resp.headers.get('Location', '').lower()
    trap_keywords = ('login', 'signin', 'index.', 'home', 'default', 'error', '404')
    return any(keyword in location for keyword in trap_keywords)


def looks_like_text_backup(suffix: str, content_type: str) -> bool:
    text_like_suffixes = {'.sql', '.bak.sql', '.dump', '.dump.sql', '.sql.bak'}
    return suffix in text_like_suffixes and any(
        token in content_type for token in ('text/plain', 'application/sql', 'application/octet-stream')
    )


def has_known_magic(sample: bytes, suffix: str) -> bool:
    checks = {
        '.zip': lambda data: data.startswith(b'PK\x03\x04') or data.startswith(b'PK\x05\x06') or data.startswith(b'PK\x07\x08'),
        '.jar': lambda data: data.startswith(b'PK\x03\x04'),
        '.war': lambda data: data.startswith(b'PK\x03\x04'),
        '.gz': lambda data: data.startswith(b'\x1f\x8b\x08'),
        '.sql.gz': lambda data: data.startswith(b'\x1f\x8b\x08'),
        '.tgz': lambda data: data.startswith(b'\x1f\x8b\x08'),
        '.tar.gz': lambda data: data.startswith(b'\x1f\x8b\x08'),
        '.bz2': lambda data: data.startswith(b'BZh'),
        '.tar.bz2': lambda data: data.startswith(b'BZh'),
        '.xz': lambda data: data.startswith(b'\xfd7zXZ\x00'),
        '.txz': lambda data: data.startswith(b'\xfd7zXZ\x00'),
        '.tar.xz': lambda data: data.startswith(b'\xfd7zXZ\x00'),
        '.7z': lambda data: data.startswith(b"7z\xbc\xaf'\x1c"),
        '.rar': lambda data: data.startswith(b'Rar!\x1a\x07\x00') or data.startswith(b'Rar!\x1a\x07\x01\x00'),
        '.sqlite': lambda data: data.startswith(b'SQLite format 3\x00'),
        '.sqlite3': lambda data: data.startswith(b'SQLite format 3\x00'),
        '.db': lambda data: data.startswith(b'SQLite format 3\x00'),
    }
    checker = checks.get(suffix)
    return checker(sample) if checker else False


def is_likely_text_error(sample: bytes) -> bool:
    probe = sample[:64].lower()
    return any(token in probe for token in (b'<!doctype', b'<html', b'<head', b'<body', b'404', b'not found', b'access denied'))


def is_likely_backup_response(resp: requests.Response) -> bool:
    content_type = resp.headers.get('Content-Type', '').lower()
    forbidden = {'html', 'text', 'xml', 'json', 'javascript', 'image', 'css', 'font', 'audio', 'video'}
    return (
        resp.status_code == 200 and
        not any(t in content_type for t in forbidden) and
        ('application' in content_type or not content_type.strip())
    )


def build_response_fingerprint(resp: requests.Response, sample: bytes = b'') -> Dict[str, str]:
    return {
        'status': str(resp.status_code),
        'content_type': normalize_header_value(resp.headers.get('Content-Type', '').split(';', 1)[0]),
        'content_length': normalize_header_value(resp.headers.get('Content-Length', '')),
        'location': normalize_header_value(resp.headers.get('Location', '')),
        'sample': sample[:64].hex()
    }


def fingerprint_matches(resp: requests.Response, fingerprint: Optional[Dict[str, str]], sample: bytes = b'') -> bool:
    if not fingerprint:
        return False

    current = build_response_fingerprint(resp, sample)

    if current['status'] != fingerprint['status']:
        return False

    if fingerprint['location'] and current['location'] == fingerprint['location']:
        return True

    same_type = current['content_type'] == fingerprint['content_type']
    same_length = fingerprint['content_length'] and current['content_length'] == fingerprint['content_length']
    same_sample = fingerprint['sample'] and current['sample'] == fingerprint['sample']

    if same_type and same_length:
        return True

    if same_type and same_sample:
        return True

    return False


def is_site_accessible(
    url: str,
    session: requests.Session,
    connect_timeout: int,
    read_timeout: int,
    proxies: Optional[Dict]
) -> Tuple[bool, str]:
    """Only skip when the target is unreachable at the network layer."""
    try:
        head_resp = session.head(
            url,
            headers=make_headers(),
            timeout=(connect_timeout, read_timeout),
            verify=False,
            allow_redirects=False,
            proxies=proxies
        )
        with head_resp:
            if head_resp.status_code < 500 or head_resp.status_code in {500, 501, 502, 503, 504}:
                return True, f"http_status_{head_resp.status_code}"

        with session.get(
            url,
            headers=make_headers(),
            timeout=(connect_timeout, read_timeout),
            verify=False,
            allow_redirects=False,
            stream=True,
            proxies=proxies
        ):
            pass
        return True, "http_response_received"
    except requests.exceptions.SSLError as exc:
        return False, f"ssl_error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        return False, f"connection_error: {exc}"
    except requests.exceptions.Timeout as exc:
        return False, f"timeout: {exc}"
    except requests.RequestException as exc:
        return False, f"request_error: {exc}"


def log_success(url: str, content_length: str, output_path: Path) -> None:
    size_str = naturalsize(int(content_length), binary=True)
    logging.warning(f"[ success ] {url}  size: {size_str}")

    with OUTPUT_LOCK:
        with open(output_path, 'a', encoding='utf-8') as f:
            f.write(f"{url} size:{size_str}\n")


def get_not_found_fingerprint(
    base_url: str,
    session: requests.Session,
    connect_timeout: int,
    read_timeout: int,
    proxies: Optional[Dict]
) -> Optional[Dict[str, str]]:
    marker = f"__ihoney_not_found__{uuid.uuid4().hex}.txt"
    probe_url = urljoin(base_url.rstrip('/') + '/', marker)

    try:
        head_resp = session.head(
            probe_url,
            headers=make_headers(),
            timeout=(connect_timeout, read_timeout),
            allow_redirects=False,
            verify=False,
            proxies=proxies
        )
        with head_resp:
            if head_resp.status_code in {404, 410, 301, 302, 303, 307, 308, 200, 403}:
                return build_response_fingerprint(head_resp)
    except requests.RequestException:
        pass

    try:
        with closing(session.get(
            probe_url,
            headers=make_range_headers(),
            timeout=(connect_timeout, read_timeout),
            allow_redirects=False,
            stream=True,
            verify=False,
            proxies=proxies
        )) as resp:
            sample = resp.raw.read(64, decode_content=False)
            return build_response_fingerprint(resp, sample)
    except requests.RequestException:
        return None


def assess_head_response(resp: requests.Response, url: str, not_found_fingerprint: Optional[Dict[str, str]]) -> Tuple[bool, bool]:
    suffix = get_candidate_suffix(url)
    content_type = resp.headers.get('Content-Type', '').lower()
    content_length = resp.headers.get('Content-Length')

    if fingerprint_matches(resp, not_found_fingerprint):
        return False, False

    if resp.status_code in {404, 410}:
        return False, False

    if is_probably_redirect_trap(resp):
        return False, False

    if has_download_disposition(resp) and content_length and int(content_length) > 0:
        return True, False

    if is_likely_backup_response(resp) and content_length and int(content_length) > 0:
        return True, False

    if looks_like_text_backup(suffix, content_type) and content_length and int(content_length) > 0:
        return True, False

    should_fallback = (
        resp.status_code in {200, 206, 301, 302, 303, 307, 308, 403, 405, 501} or
        not content_length
    )
    return False, should_fallback


def check_url(
    url: str,
    session: requests.Session,
    connect_timeout: int,
    read_timeout: int,
    proxies: Optional[Dict],
    output_path: Path,
    not_found_fingerprint: Optional[Dict[str, str]]
) -> Optional[str]:
    try:
        head_resp = session.head(
            url,
            headers=make_headers(),
            timeout=(connect_timeout, read_timeout),
            allow_redirects=False,
            verify=False,
            proxies=proxies
        )
        with head_resp:
            is_hit, should_fallback = assess_head_response(head_resp, url, not_found_fingerprint)
            if is_hit:
                log_success(url, head_resp.headers['Content-Length'], output_path)
                return None
            if not should_fallback:
                return None

        suffix = get_candidate_suffix(url)
        with closing(session.get(
            url,
            headers=make_range_headers(),
            timeout=(connect_timeout, read_timeout),
            allow_redirects=False,
            stream=True,
            verify=False,
            proxies=proxies
        )) as resp:
            sample = b''

            if fingerprint_matches(resp, not_found_fingerprint):
                return None

            if resp.status_code in {404, 410} or is_probably_redirect_trap(resp):
                return None

            if not is_likely_backup_response(resp):
                content_type = resp.headers.get('Content-Type', '').lower()
                if not has_download_disposition(resp) and not looks_like_text_backup(suffix, content_type):
                    return None

            cl = resp.headers.get('Content-Length')
            if cl and int(cl) > 0 and (has_download_disposition(resp) or is_likely_backup_response(resp)):
                log_success(url, cl, output_path)
                return None

            sample = resp.raw.read(64, decode_content=False)
            if not sample:
                return None

            if fingerprint_matches(resp, not_found_fingerprint, sample):
                return None

            if has_known_magic(sample, suffix):
                size_value = cl if cl and int(cl) > 0 else str(len(sample))
                log_success(url, size_value, output_path)
                return None

            if looks_like_text_backup(suffix, resp.headers.get('Content-Type', '').lower()) and not is_likely_text_error(sample):
                size_value = cl if cl and int(cl) > 0 else str(len(sample))
                log_success(url, size_value, output_path)
        return None

    except requests.exceptions.Timeout:
        return 'timeout'
    except requests.RequestException:
        return None
    except Exception as e:
        logging.debug(f"[err] {url} → {str(e)}")
        return None


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
    connect_timeout: int,
    read_timeout: int,
    max_timeouts: int,
    proxies: Optional[Dict],
    output_path: Path,
    prefixes: List[str]
) -> None:
    session = build_session(max_workers)

    total_candidates = 0
    total_scanned = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for idx, base_url in enumerate(targets, 1):
            print(f"[{idx}/{len(targets)}] {base_url}")
            accessible, reason = is_site_accessible(base_url, session, connect_timeout, read_timeout, proxies)
            if not accessible:
                print(f"  -> skip: {reason}")
                continue

            not_found_fingerprint = get_not_found_fingerprint(base_url, session, connect_timeout, read_timeout, proxies)

            candidates = generate_candidates(base_url, prefixes, SUFFIX_FORMAT)
            site_count = len(candidates)
            total_candidates += site_count

            if site_count == 0:
                print("  -> skip: no candidates generated")
                continue

            with tqdm(total=site_count, desc=f"Scanning {base_url}", unit="req", leave=False) as pbar:
                max_in_flight = max(max_workers, min(max_workers * 2, 200))
                candidate_iter = iter(candidates)
                in_flight = set()
                timeout_count = 0
                site_aborted = False

                def submit_next() -> bool:
                    if site_aborted:
                        return False
                    try:
                        candidate = next(candidate_iter)
                    except StopIteration:
                        return False

                    future = executor.submit(
                        check_url,
                        candidate,
                        session,
                        connect_timeout,
                        read_timeout,
                        proxies,
                        output_path,
                        not_found_fingerprint
                    )
                    in_flight.add(future)
                    return True

                for _ in range(min(max_in_flight, site_count)):
                    if not submit_next():
                        break

                while in_flight:
                    done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                    for future in done:
                        result = future.result()
                        pbar.update(1)
                        total_scanned += 1
                        if result == 'timeout':
                            timeout_count += 1
                            if timeout_count > max_timeouts:
                                site_aborted = True
                                print(f"  -> skip: too many timeouts ({timeout_count}>{max_timeouts})")
                                for pending in in_flight:
                                    pending.cancel()
                                in_flight.clear()
                                skipped_count = sum(1 for _ in candidate_iter)
                                if skipped_count:
                                    pbar.update(skipped_count)
                                    total_scanned += skipped_count
                                break
                        submit_next()
                    if site_aborted:
                        break

    print(f"Scan completed | Total candidates: {total_candidates} | Scanned: {total_scanned}")


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
    parser.add_argument('--connect-timeout', dest='connect_timeout', type=int, default=3, help="TCP connect timeout in seconds (default: 3)")
    parser.add_argument('--read-timeout', dest='read_timeout', type=int, default=10, help="Response header/read timeout in seconds (default: 10)")
    parser.add_argument('--max-timeouts', dest='max_timeouts', type=int, default=10, help="Skip a site after this many candidate timeouts (default: 10)")

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
        except Exception as e:
            logging.warning(f"Failed to load custom dict: {e}")

    if args.connect_timeout < 1:
        parser.error("--connect-timeout must be greater than 0")
    if args.read_timeout < 1:
        parser.error("--read-timeout must be greater than 0")
    if args.max_timeouts < 1:
        parser.error("--max-timeouts must be greater than 0")

    connect_timeout = args.connect_timeout
    read_timeout = args.read_timeout

    scan_targets(
        targets,
        args.max_threads,
        connect_timeout,
        read_timeout,
        args.max_timeouts,
        proxies,
        output_path,
        active_prefixes
    )
