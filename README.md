# ihoneyBakFileScan_Modify

[![GitHub stars](https://img.shields.io/github/stars/VMsec/ihoneyBakFileScan_Modify?style=social)](https://github.com/VMsec/ihoneyBakFileScan_Modify)
[![GitHub forks](https://img.shields.io/github/forks/VMsec/ihoneyBakFileScan_Modify?style=social)](https://github.com/VMsec/ihoneyBakFileScan_Modify)

一款多线程批量网站备份文件泄露扫描器。

自动根据域名生成变体字典，扫描常见备份文件（如 .zip、.sql、.bak、.tar.gz 等），优化内存占用，支持代理、自定义字典、进度条显示。

![ihoneyBakFileScan_Modify](https://socialify.git.ci/VMsec/ihoneyBakFileScan_Modify/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E5%A4%9A%E7%BA%BF%E7%A8%8B%E6%89%B9%E9%87%8F%E7%BD%91%E7%AB%99%E5%A4%87%E4%BB%BD%E6%96%87%E4%BB%B6%E6%89%AB%E6%8F%8F%E5%99%A8%EF%BC%8C%E5%A2%9E%E5%8A%A0%E6%96%87%E4%BB%B6%E8%A7%84%E5%88%99%EF%BC%8C%E4%BC%98%E5%8C%96%E5%86%85%E5%AD%98%E5%8D%A0%E7%94%A8%E3%80%82&font=Inter&forks=1&issues=1&language=1&name=1&owner=1&pattern=Floating%20Cogs&pulls=1&stargazers=1&theme=Dark)

## 快速使用

从文件读取的 URL 建议格式（每行一个）：

```Bash
https://www.example.com
http://test.com:8080
https://sub.domain.net/
```
在 1GB 内存 VPS 上，建议线程数 100–200（500 线程可能导致连接池警告或网络瓶颈）：

```bash
python3 ihoneyBakFileScan_Modify.py -t 150 -f url.txt -o result.txt

Bashpython3 ihoneyBakFileScan_Modify.py -u https://example.com -t 100 -o result.txt
```

# 1. 简介
 ## 1.1 网站备份文件泄露的危害

攻击者可直接下载数据库备份（.sql/.sql.gz）、源码备份（.zip/.tar.gz/.rar/.7z），获取管理员账号、密钥、敏感配置。

泄露物理路径、后台地址、服务器信息，便于进一步渗透。

大文件备份往往包含更多历史版本数据，易被用于代码审计或供应链攻击。

高危漏洞之一，可能导致整站被接管。

## 1.2 依赖环境

pip install -r requirements.txt

```Bash
textrequests[socks]>=2.32.0
fake-useragent>=2.0.0
humanize>=4.9.0
tqdm>=4.66.0
```

## 1.3 核心功能

常见备份后缀（可自行扩展）：text.7z .backup .bak .bak.sql .bz2 .db .dmp .dump .dump.sql .gz .jar .rar .sql .sql.bak .sql.gz .sqlite .sqlite3 .tar .tar.bz2 .tar.gz .tar.tgz .tar.xz .tbz .tbz2 .tgz .txz .war .xz .zip

自动生成域名变体（根据域名智能拆分）：

https://baidu.com → ['baidu.com', 'baiducom', 'baidu_com', 'baidu', 'com']

https://www.baidu.com → ['www.baidu.com', 'wwwbaiducom', 'www_baidu_com', 'baidu', 'www', ...]

多级子域（如 aaa.bbb.ccc.ddd.com） → 约 9 个变体（完整、去点、换下划线、去子域、去 TLD 等）

## 文件名字典（代码中可切换）：

77 条默认（推荐，轻量）：tmp_info_dic = ['1', '127.0.0.1', '2010'...'2026', 'admin', 'backup', 'bak', 'database', 'db', 'dump', 'wwwroot', 'root', 'log', ...]

130 条扩展（已注释掉，可手动切换，包含中文如 '数据库备份'）：tmp_info_dic = ['0','00','000','数据库备份',...]


# 2. 使用方式

```Bash
  -h, --help            显示帮助
  -f, --url-file        批量 URL 文件（每行一个）
  -t, --thread          最大线程数（默认 20，建议 100-200）
  --connect-timeout     TCP 连接超时秒数（默认 3）
  --read-timeout        响应头/读取超时秒数（默认 10）
  --max-timeouts        单站候选请求超时超过该值后跳过该站（默认 10）
  -u, --url             单站点 URL
  -d, --dict-file       自定义文件名字典文件（追加到默认字典）
  -o, --output-file     输出结果文件（默认 result.txt）
  -p, --proxy           代理（如 socks5://127.0.0.1:1080 或 socks5h://user:pass@host:port）

# 批量扫描
python3 ihoneyBakFileScan_Modify.py -t 150 -f targets.txt -o leaks.txt

# 批量扫描 + 超时控制
python3 ihoneyBakFileScan_Modify.py -t 100 --connect-timeout 3 --read-timeout 10 --max-timeouts 10 -f targets.txt -o leaks.txt

# 单站点 + 代理 + 自定义字典
python3 ihoneyBakFileScan_Modify.py -u https://target.com -t 100 -p socks5h://127.0.0.1:1080 -d mydict.txt -o result.txt
```


# 3. 更新历史

2026：fake-useragent\humanize\tqdm by Grok

2023.4.19：添加代理支持（socks5/http）

2022.9.15：更改扫描逻辑，修复大列表内存占用过大（逐站点处理）

2022.6.22：增加结果写入、域名规则、随机 UA（原 fake_headers）、线程池修复死锁

2022.2.8：增加 fuzz 规则、hurry.filesize、大小判断、多线程

# 4. 注意事项

仅限合法授权测试使用，严禁非法扫描。
