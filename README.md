# ihoneyBakFileScan_Modify 

![ihoneyBakFileScan_Modify](https://socialify.git.ci/VMsec/ihoneyBakFileScan_Modify/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E5%A4%9A%E7%BA%BF%E7%A8%8B%E6%89%B9%E9%87%8F%E7%BD%91%E7%AB%99%E5%A4%87%E4%BB%BD%E6%96%87%E4%BB%B6%E6%89%AB%E6%8F%8F%E5%99%A8%EF%BC%8C%E5%A2%9E%E5%8A%A0%E6%96%87%E4%BB%B6%E8%A7%84%E5%88%99%EF%BC%8C%E4%BC%98%E5%8C%96%E5%86%85%E5%AD%98%E5%8D%A0%E7%94%A8%E3%80%82&font=Inter&forks=1&issues=1&language=1&name=1&owner=1&pattern=Floating%20Cogs&pulls=1&stargazers=1&theme=Dark)

## 快速使用
从文件读取的url建议为以下格式

```
https://www.baidu.com
http://www.baidu.com
https://www.baidu.com:8443
```

经测试 1h1g vps 500线程可以拉满

```
python3 ihoneyBakFileScan_Modify.py -t 500 -f url.txt -o result.txt
```

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
python3 -m pip install -r requirements.txt

fake_headers==1.0.2
hurry==1.1
hurry.filesize==0.9
requests==2.25.1
```
##### 1.3 工具核心：

1. 常见后缀：
```
['.zip','.rar','.tar.gz','.tgz','.tar.bz2','.tar','.jar','.war','.7z','.bak','.sql','.gz','.sql.gz','.tar.tgz','.backup']
```
2. 根据域名自动生成相关扫描字典:
```
python3 ihoneyBakFileScan_Modify.py -u https://baidu.com -t 1000 -o test.txt
['baidu.com', 'baiducom', 'baidu_com', 'com', 'com', 'com', 'baidu', 'com']

python3 ihoneyBakFileScan_Modify.py -u https://www.baidu.com -t 1000 -o test.txt
['www.baidu.com', 'wwwbaiducom', 'www_baidu_com', 'baiducom', 'baidu.com', 'baidu_com', 'www', 'baidu']

python3 ihoneyBakFileScan_Modify.py -u https://aaa.www.baidu.com -t 1000 -o test.txt
['aaa.www.baidu.com', 'aaawwwbaiducom', 'aaa_www_baidu_com', 'wwwbaiducom', 'www.baidu.com', 'www_baidu_com', 'aaa', 'www']

python3 ihoneyBakFileScan_Modify.py -u https://aaa.bbb.www.baidu.com -t 1000 -o test.txt
['aaa.bbb.www.baidu.com', 'aaabbbwwwbaiducom', 'aaa_bbb_www_baidu_com', 'bbbwwwbaiducom', 'bbb.www.baidu.com', 'bbb_www_baidu_com', 'aaa', 'bbb']
```
3. 常见备份文件名，字典于代码中可自行切换,:
```
#77
tmp_info_dic = ['1','127.0.0.1','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','__zep__/js','admin','archive','asp','aspx','auth','back','backup','backups','bak','bbs','bin','clients','code','com','customers','dat','data','database','db','dump','engine','error_log','faisunzip','files','forum','home','html','index','joomla','js','jsp','local','localhost','master','media','members','my','mysql','new','old','orders','php','sales','site','sql','store','tar','test','user','users','vb','web','website','wordpress','wp','www','wwwroot','root']

#130
#tmp_info_dic = ['__zep__/js','0','00','000','012','1','111','123','127.0.0.1','2','2010','2011','2012','2013','2014','2015','2016','2017','2018','2019','2020','2021','2022','2023','2024','2025','234','3','333','4','444','5','555','6','666','7','777','8','888','9','999','a','about','admin','app','application','archive','asp','aspx','auth','b','back','backup','backups','bak','bbs','beifen','bin','cache','clients','code','com','config','core','customers','dat','data','database','db','download','dump','engine','error_log','extend','files','forum','ftp','home','html','img','include','index','install','joomla','js','jsp','local','login','localhost','master','media','members','my','mysql','new','old','orders','output','package','php','public','root','runtime','sales','server','shujuku','site','sjk','sql','store','tar','template','test','upload','user','users','vb','vendor','wangzhan','web','website','wordpress','wp','www','wwwroot','wz','数据库','数据库备份','网站','网站备份']
```
4. 自动记录扫描成功的备份地址到指定的文件
```
例如 result.txt

https://www.baidu.com/baidu.tar.gz  size:1k
https://www.baidu.comn/www.baidu.com.zip  size:10M
```

## 2. 使用方式
```
参数：
    -h --help           查看工具使用帮助
    -f --url-file       批量时指定存放url的文件,每行url需要指定http://或者https://，否则默认使用http://
    -t --thread         指定线程数，建议100
    -u --url            单个url扫描时指定url
    -d --dict-file      自定义扫描字典
    -o --output-file    结果写入的文件名
    -p --proxy          代理服务，例：socks5://127.0.0.1:1080
使用:
    批量url扫描    python3 ihoneyBakFileScan_Modify.py -t 100 -f url.txt -o result.txt
    单个url扫描    python3 ihoneyBakFileScan_Modify.py -u https://www.baidu.com/ -o result.txt
                  python3 ihoneyBakFileScan_Modify.py -u www.baidu.com -o result.txt
                  python3 ihoneyBakFileScan_Modify.py -u www.baidu.com -d dict.txt -o result.txt
```
# 2023.4.19 添加、修改内容

添加代理功能

# 2022.9.15 添加、修改内容

更改扫描逻辑，修复待扫描列表过长导致的内存占用过大

# 2022.6.22 添加、修改内容

增加结果写入指定文件名

增加域名扫描规则

增加扫描随机User-Agent（pip3 install fake_headers）

修复多线程扫描死锁的bug，改为线程池


# 2022.2.8 添加、修改内容

增加备份文件fuzz规则

修改备份文件大小判断方式（pip3 install hurry.filesize）

修改备份文件是否存在的判断规则

修改为多线程扫描，内存占用更小

