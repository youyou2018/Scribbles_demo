#!/usr/bin/python
#coding=utf-8
import sys  
reload(sys)  
sys.setdefaultencoding('utf8')   
import hashlib
import os
import shutil
from bottle import route,run,request,static_file, jinja2_view, redirect, default_app
import pprint
from xml.dom import  minidom
import docx
import datetime
import sqlite3
import geoip2.database
import ConfigParser
import ipcalc
from beaker.middleware import SessionMiddleware
import json

session_opts = {
        'session.type':'file',
        'session.cookei_expires':300,
        'session.data_dir':'./sessions',
        'sessioni.auto':True
        }

cf = ConfigParser.ConfigParser()
cf.read("./ip.conf")
webIP = cf.get("reverse", "ip")

currentDir = os.getcwd()
if not os.path.exists("orig"):
    os.mkdir("orig")

if not os.path.exists("output"):
    os.mkdir("output")

if not os.path.exists("temp"):
    os.mkdir("temp")

def generate_rid(fileStr=None):
    document = docx.Document(fileStr)
    document_parts = document.part
    rels = document_parts.rels
    rids  = []
    for rel in rels:
        rids.append(rel)
    rids.sort()
    return "rId%s" % str(int(rids[-1][3:]) + 1)


def change_rels_file(rels=None, rId=None, webIP=None, md5Str=None):
    oldData = ""
    with open(rels) as f:
        oldData = f.read()

    afterRel="""<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="http://%s/img/%s.jpg" TargetMode="External"/></Relationships>""" %(rId, webIP, md5Str)
    beforeRel = """</Relationships>"""

    newData = oldData.replace(beforeRel, afterRel)
    with open(rels, "wb") as f:
        f.write(newData)



def change_document(docuFile=None, rId=None, md5Str=None):
    docu01 = minidom.parse(docuFile)
    doc01 = docu01.documentElement
    body01 = doc01.getElementsByTagName("w:body")
    wp01 = body01[0].getElementsByTagName("w:p")[0]
    beforersid = wp01.getAttribute("w:rsidRDefault")
    wp01.setAttribute("w:rsidRDefault", "%s_justatestjustatestjustatest" % beforersid)
    f = open("/tmp/%s" % md5Str, 'w')
    docu01.writexml(f)
    f.close()

    documentData = """"><w:r><w:rPr><w:rFonts w:hint="eastAsia"/><w:noProof/></w:rPr><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="12700" cy="12700"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:docPr id="1" name="图片 1"/><wp:cNvGraphicFramePr/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="1" name=""/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:link="%s"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="12700" cy="12700"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>""" % rId
    documentData01 = """_justatestjustatestjustatest">"""

    documentOldData = ""
    documentNewData = ""
    with open("/tmp/%s" % md5Str) as f:
        documentOldData = f.read()
    documentNewData = documentOldData.replace(documentData01, documentData)

    with open(docuFile, "wb") as f:
        f.write(documentNewData)

def CalcMD5(filepath):
    with open(filepath, 'rb') as f:
        md5obj = hashlib.md5()
        md5obj.update(f.read())
        hashs = md5obj.hexdigest()
        return hashs.upper()

def check_file(fileMd5Str=None):
    cxn = sqlite3.connect('files_log.db')
    cur = cxn.cursor()
    cur.execute('CREATE TABLE if not exists log_files(date text, orig text,'
                'logNumber INTEGER, md5sum text)')
    # insertStr = "INSERT into log VALUES(\"" +clientIp+"\",\""+macHash[clientIp]+"\",\""+nowtime+ "\",\""+injectMode+"\",\""+softwareName+"\")"
    # cur.execute(insertStr)
    selectStr = "select * from log_files WHERE md5sum=\"%s\"" % fileMd5Str
    cur.execute(selectStr)
    if cur.fetchone():
        cur.close()
        cxn.commit()
        cxn.close()
        return True
    else:
        cur.close()
        cxn.commit()
        cxn.close()
        return False

def insert_ip_log(fileMd5Str=None, ip=None, ua=None):
    offices = {"Office 9.0": "Office 2000",
               "Office 10": "Office XP",
               "Office 11": "Office 2003",
               "Office 12": "Office 2007",
               "Office 14": "Office 2010",
               "Office 15": "Office 2013",
               "Office 16": "Office 365"}

    windows = {"Windows NT 5.0": "Windwos 2000",
               "Windows NT 5.1": "Windwos XP",
               "Windwos NT 5.2": "Windwos XP|Windows Server 2003|Windows Server 2003 R2",
               "Windows NT 6.0": "Windwos Vista|Windows Server 2008",
               "Windows NT 6.1": "Windwos 7|Windows Server 2008 R2|Windows Home Server 2011",
               "Windows NT 6.2": "Windwos 8|Windwos Server 2012",
               "Windows NT 6.3": "Windwos 8.1|Windwos Server 2012 R2",
               "Windows NT 10": "Windwos 10|Windows Serve 2016"}

    offver = None
    winver = None

    for officeVer in offices.keys():
        if officeVer in ua:
            offver = offices[officeVer]
    for winver1 in windows.keys():
        if winver1 in ua:
            winver =  windows[winver1]
    dt = datetime.datetime.now()
    nowtime = str(dt.strftime('%Y-%m-%d %H:%M:%S'))

    cxn = sqlite3.connect('files_log.db')
    cur = cxn.cursor()
    cur.execute('CREATE TABLE if not exists log_ips(date text, ip text,'
                'offver text, winver text, ua text, md5sum text)')
    insertStr = "INSERT into log_ips VALUES(\"" +nowtime+"\",\""+ip+"\",\""+offver+"\",\""+winver+"\",\""+ua+"\",\""+fileMd5Str+"\")"

    cur.execute(insertStr)
    cxn.commit()

    selectStr = "select logNumber from log_files WHERE md5sum=\"%s\"" % fileMd5Str

    cur.execute(selectStr)

    numb = cur.fetchone()
    number = int(numb[0])+1

    updateStr = "UPDATE log_files set logNumber=%s WHERE md5sum=\"%s\"" % (int(number), fileMd5Str)
    cur.execute(updateStr)

    cxn.commit()
    cur.close()
    cxn.commit()
    cxn.close()

def insert_docx_file(fileMd5Str=None,filename=None):
    dt = datetime.datetime.now()
    nowtime = str(dt.strftime('%Y-%m-%d %H:%M:%S'))
    cxn = sqlite3.connect('files_log.db')
    cur = cxn.cursor()
    # cur.execute('CREATE TABLE if not exists log_files(id INTEGER PRIMARY KEY AUTOINCREMENT, date text, orig text,'
    #             'logNumber INTEGER, md5sum text)')
    insertStr = "INSERT into log_files VALUES(\"" +nowtime+"\",\""+filename+ "\",0,\""+fileMd5Str+"\")"
    cur.execute(insertStr)
    cur.close()
    cxn.commit()
    cxn.close()

def get_docx_file():
    conn = sqlite3.connect("./files_log.db")
    cu = conn.cursor()
    cu.execute('CREATE TABLE if not exists log_files(date text, orig text,'
                'logNumber INTEGER, md5sum text)')
    conn.commit()
    cu.execute("select ROWID,* from log_files")
    logs = cu.fetchall()
    cu.close()
    conn.close()
    return  logs





def get_ip_logs(name=None):
    conn = sqlite3.connect("./files_log.db")
    cu = conn.cursor()
    selectStr = "select ROWID,* from log_ips WHERE md5sum=\"%s\"" % name
    cu.execute(selectStr)
    logs = cu.fetchall()
    cu.close()
    conn.close()
    return  logs


@route('/logfile.json', method="GET")
def do_get_json():
    logs = get_docx_file()

    docx_logs = []
    for docx_log in logs:
        tempLog = {}
        tempLog["id"] = docx_log[0]
        tempLog["del"] = "<a href=\"javascript:if(confirm('确实要删除?'))location='/delfile/%s/%s'\">%s</a>" % (
        docx_log[0], docx_log[4], docx_log[0])
        tempLog["date"] = docx_log[1]
        tempLog["ofile"] = "<a href=\"/orig/%s.docx\">%s</a>" % (docx_log[4], docx_log[2])
        tempLog["cfile"] = "<a href=\"/output/%s.docx\">%s</a>" % (docx_log[4], docx_log[2])
        tempLog["num"] = docx_log[3]
        tempLog["info"] = "<a href=\"/info/%s\">详细</a>" % (docx_log[4])

        docx_logs.append(tempLog)

    docx_logs01 = {}
    docx_logs01["data"] = docx_logs

    return json.dumps(docx_logs01)

# @route('/delfile/<name:path>', method="GET")
# def do_get_delfile(name):
#     conn = sqlite3.connect("./files_log.db")
#     cu = conn.cursor()
#     deleteStr = "delete from log_files where rowid=%s" % name
#     print deleteStr
#     cu.execute(deleteStr)
#     conn.commit()
#     cu.close()
#     conn.close()
#     redirect("/")

@route('/delfile/<name:path>/<name1:path>', method="GET")
def do_get_delfile(name, name1):
    conn = sqlite3.connect("./files_log.db")
    cu = conn.cursor()
    deleteStr = "delete from log_files where rowid=%s" % name
    print deleteStr
    cu.execute(deleteStr)
    conn.commit()
    cu.close()
    conn.close()
    print name1
    os.system("rm -rf ./orig/%s.docx" % name1)
    os.system("rm -rf ./output/%s.docx" % name1)
    redirect("/")


@route('/delip/<name:path>/<fileMd5Str:path>', method="GET")
def do_get_delip(name, fileMd5Str):
    conn = sqlite3.connect("./files_log.db")
    cu = conn.cursor()
    deleteStr = "delete from log_ips where rowid=%s" % name
    print deleteStr
    cu.execute(deleteStr)
    conn.commit()
    selectStr = "select logNumber from log_files WHERE md5sum=\"%s\"" % fileMd5Str

    cu.execute(selectStr)

    numb = cu.fetchone()
    number = int(numb[0])-1

    updateStr = "UPDATE log_files set logNumber=%s WHERE md5sum=\"%s\"" % (int(number), fileMd5Str)
    cu.execute(updateStr)
    conn.commit()
    cu.close()
    conn.close()
    redirect("/")



@route('/',method="GET")
#@jinja2_view('list1.html')
@jinja2_view('index.html')
def do_get_index():
    s = request.environ.get('beaker.session')
    if not s.has_key("username"):
        redirect("/login")
    global webIP
    logs = get_docx_file()
    print webIP
    return {"logs":logs, "reverseip":webIP}


@route('/info/<name:path>', method="GET")
@jinja2_view('info.html')
# @jinja2_view('test2.html')
def do_get_info(name):
    logs = get_ip_logs(name)
    reader = geoip2.database.Reader("./GeoLite2-City.mmdb")
    for i, log in enumerate(logs):
        try:
            response = reader.city(log[2])
            list2 = list(log)
            list2.append(response.country.name)
            list2.append(response.city.name)
            list2.append(response.location.latitude)
            list2.append(response.location.longitude)
            logs[i] = tuple(list2)
        except geoip2.errors.AddressNotFoundError:
            pass
    return {"logs":logs}

@route('/img/<name:path>', method="GET")
def do_get_img(name):
    insert_ip_log(name[:-4],request.environ.get('REMOTE_ADDR'),request.environ.get("HTTP_USER_AGENT"))
    return


@route('/orig/<name:path>', method="GET")
def do_get_orig(name):
    return static_file(name, root="%s/orig" % currentDir, download=True)


@route('/output/<name:path>', method="GET")
def do_get_orig(name):
    return static_file(name, root="%s/output" % currentDir, download=True)

@route('/changeip', method="POST")
def do_post_chaneip():
    global webIP
    chaneip = request.forms.get("ip")
    try:
        aip = ipcalc.IP(chaneip)
        cf.set("reverse", "ip", chaneip)
        cf.write(open("./ip.conf", "w"))
        webIP = chaneip
        redirect("/")
    except ValueError:
        return "wrong ip address"


@route('/post', method="POST")
def do_post_index():
    try:
        os.chdir(currentDir)
        upload = request.files.get("file")
        print upload.filename
        upload.save("./temp/%s" % upload.filename)
        inputFile = "./temp/%s" % upload.filename
        fileMd5Str = CalcMD5(inputFile)
        if  check_file(fileMd5Str):
            os.system("rm -rf ./temp/*")
            return "has file"
        os.chdir("./temp")
        outputFile = "%s.docx" % fileMd5Str
        os.system("7z x %s" % upload.filename)
        rid = generate_rid(upload.filename)
        change_rels_file("./word/_rels/document.xml.rels", rId=rid, webIP=webIP, md5Str=fileMd5Str)
        change_document("./word/document.xml", rId=rid, md5Str=fileMd5Str)
        os.system("zip -r %s [Content_Types].xml docProps _rels word" % outputFile)
        os.system("cp %s ../output" % outputFile)
        os.system("cp %s ../orig/%s" % (upload.filename,outputFile))
        os.chdir(currentDir)
        os.system("rm -rf ./temp/*")
        insert_docx_file(fileMd5Str, upload.filename)
    except:
        pass
    redirect("/")


@route('/login', method="POST")
def do_post_login():
    username = request.forms.get("username")
    password = request.forms.get("password")
    print username
    print password
    if "admin" == username.strip() and "admin" == password.strip():
        print "ok!"
        s = request.environ.get('beaker.session')
        s["username"] = "admin"
        s.save()
        redirect("/")
    else:
        print "failed"
        redirect("/login")


@route('/login', method="GET")
@jinja2_view('login.html')
def do_get_login():
    return {"login":"fgdg"}


# run(host="0.0.0.0", port=80)

app = default_app()
app = SessionMiddleware(app, session_opts)
run(app=app, host="0.0.0.0", port=80)