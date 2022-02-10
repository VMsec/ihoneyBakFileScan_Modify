# ihoneyBakFileScan_Modify 多进程批量网站备份文件泄露扫描工具

# 2022.2.8 添加、修改内容

增加备份文件fuzz规则

修改备份文件大小判断方式（hurry-filesize）

修改备份文件是否存在的判断规则

修改为多线程扫描，内存占用更小

经测试 1h1g vps 500线程可以拉满

```
python3 bakfilescan.py -t 500 -f url.txt
```


[![python3](https://img.shields.io/badge/python-3.5.3-brightgreen.svg?style=plastic)](https://www.python.org/)
[![requests](https://img.shields.io/badge/requests-2.19.1-brightgreen.svg?longCache=true&style=plastic)](http://www.python-requests.org/)
[![pip3.5](https://img.shields.io/badge/pip3.5-10.0.1-brightgreen.svg?longCache=true&style=plastic)](https://pypi.org/project/pip/)

## 1. 简介

##### 1.1 网站备份文件泄露可能造成的危害：
```
1. 网站存在备份文件：网站存在备份文件，例如数据库备份文件、网站源码备份文件等，攻击者利用该信息可以更容易得到网站权限，导致网站被黑。
2. 敏感文件泄露是高危漏洞之一，敏感文件包括数据库配置信息，网站后台路径，物理路径泄露等，此漏洞可以帮助攻击者进一步攻击，敞开系统的大门。
3. 由于目标备份文件较大（xxx.G），可能存在更多敏感数据泄露
4. 该备份文件被下载后，可以被用来做代码审计，进而造成更大的危害
5. 该信息泄露会暴露服务器的敏感信息，使攻击者能够通过泄露的信息进行进一步入侵。
```
##### 1.2 依赖环境
```
开发环境：
python3   python3.5.3
pip3.5    pip 10.0.1
requests  2.19.1
```
```
安装第三方依赖库：
pip3.5 install requests
pip3 install hurry-filesize
```

##### 1.3 工具核心：
```
1. 常见后缀：
   * '.rar', '.zip', '.gz', '.sql.gz', '.tar.gz' ...
2. 文件头识别:
   * rar:526172211a0700cf9073
   * zip:504b0304140000000800
   * gz：1f8b080000000000000b，也包括'.sql.gz'，取'1f8b0800' 作为keyword
   * tar.gz: 1f8b0800
   * sql：每种导出方式有不同的文件头
       * Adminer：  
       * mysqldump：     
       * phpMyAdmin：
       * navicat：   
3. 数据库备份导出方式识别：
   * 导出方式                      文件头字符:                    前10个16进制字符：
   * mysqldump:                   -- MySQL dump:               2d2d204d7953514c
   * phpMyAdmin:                  -- phpMyAdmin SQL Dump:      2d2d207068704d794164
   * navicat:                     /* Navicat :                 2f2a0a204e617669636174
   * Adminer:                     -- Adminer x.x.x MySQL dump: 2d2d2041646d696e6572  (5月9日新增xxx.sql)
   * Navicat MySQL Data Transfer: /* Navicat:                  2f2a0a4e617669636174
   * 一种未知导出方式:               -- -------:                  2d2d202d2d2d2d2d2d2d
4. 根据域名自动生成相关扫描字典:
    ➜  ihoneyBakFileScan python3.5 ihoneyBakFileScan.py -u https://www.ihoney.net.cn
    [ ] https://www.ihoney.net.cn/__zep__/js.zip
    [ ] https://www.ihoney.net.cn/faisunzip.zip
    [ ] https://www.ihoney.net.cn/www.ihoney.net.cn.rar
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.rar
    [ ] https://www.ihoney.net.cn/ihoneynetcn.rar
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.rar
    [ ] https://www.ihoney.net.cn/www.rar
    [ ] https://www.ihoney.net.cn/ihoney.rar
    [*] https://www.ihoney.net.cn/www.ihoney.net.cn.zip  size:0M
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.zip
    [ ] https://www.ihoney.net.cn/ihoneynetcn.zip
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.zip
    [ ] https://www.ihoney.net.cn/www.zip
    [ ] https://www.ihoney.net.cn/ihoney.zip
    [ ] https://www.ihoney.net.cn/www.ihoney.net.cn.gz
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.gz
    [ ] https://www.ihoney.net.cn/ihoneynetcn.gz
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.gz
    [ ] https://www.ihoney.net.cn/www.gz
    [ ] https://www.ihoney.net.cn/ihoney.gz
    [ ] https://www.ihoney.net.cn/www.ihoney.net.cn.sql.gz
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.sql.gz
    [ ] https://www.ihoney.net.cn/ihoneynetcn.sql.gz
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.sql.gz
    [ ] https://www.ihoney.net.cn/www.sql.gz
    [ ] https://www.ihoney.net.cn/ihoney.sql.gz
    [ ] https://www.ihoney.net.cn/www.ihoney.net.cn.tar.gz
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.tar.gz
    [ ] https://www.ihoney.net.cn/ihoneynetcn.tar.gz
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.tar.gz
    [ ] https://www.ihoney.net.cn/www.tar.gz
    [ ] https://www.ihoney.net.cn/ihoney.tar.gz
    [ ] https://www.ihoney.net.cn/www.ihoney.net.cn.sql
    [ ] https://www.ihoney.net.cn/wwwihoneynetcn.sql
    [ ] https://www.ihoney.net.cn/ihoneynetcn.sql
    [ ] https://www.ihoney.net.cn/ihoney.net.cn.sql
    [ ] https://www.ihoney.net.cn/www.sql
    [ ] https://www.ihoney.net.cn/ihoney.sql
5. 自动记录扫描成功的备份地址到以时间命名的文件
    例如 20180616_16-28-14.txt：
    https://www.ihoney.net.cn/ihoney.tar.gz  size:0M
    https://www.ihoney.net.cn/www.ihoney.net.cn.zip  size:0M
```

## 2. 使用方式
```
参数：
    -h --help      查看工具使用帮助
    -f --url-file  批量时指定存放url的文件,每行url需要指定http://或者https://，否则默认使用http://
    -t --thread    指定线程数，建议100
    -u --url       单个url扫描时指定url
    -d --dict-file 自定义扫描字典
使用:
    批量url扫描    python3.5 ihoneyBakFileScan.py -t 100 -f url.txt
    单个url扫描    python3.5 ihoneyBakFileScan.py -u https://www.ihoneysec.top/
                  python3.5 ihoneyBakFileScan.py -u www.ihoney.net.cn
                  python3.5 ihoneyBakFileScan.py -u www.ihoney.net.cn -d dict.txt
```

## 3. ChangeLog:
```
[2018.04.20]  首发T00ls：支持rar,zip后缀备份文件头识别，根据域名自动生成相关扫描字典，自动记录扫描成功的备份地址到文件
[2018.04.26]
              在原本扫描成功的备份地址后增加了备份大小，以方便快速识别有效备份。
              增加了.sql文件识别，也是识别文件头的方式，文件头我目前检测到三种，分别是不同方式导出的：1.mysql，2.phpmyadmin，3.navicat。
[2018.05.19]  新增识别Adminer导出的两种格式：baidu.sql、baodu.sql.gz
[2018.05.31]  新增Navicat MySQL Data Transfer备份导出方式和另一种未知导出方式
[2018.06.16]  修复支持https站扫描，并从旧项目中抽出来独立作为一个项目
[2018.06.18]  从多线程加队列改为多进程加进程池，提升扫描速度
```

## 4. 联系
```
* 在使用工具的过程中遇到任何异常、问题，或者你有更好的建议都可以联系作者，一起将这款不出名的小工具完善下去。
* 联系方式： QQ 102505481
```

##### 2018年06月18日22:51:11


