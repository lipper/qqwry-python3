# coding=utf-8
#
# 用于从纯真网络(cz88.net)更新qqwry.dat
# for Python 3.0+
# 来自 https://github.com/animalize/qqwry-python3
#
# 用法：
# from cz88update import updateQQwry
# result = updateQQwry(filename)  #filename为要保存的文件名
#
# updateQQwry函数返回值
# 正整数：表示已成功更新，为qqwry.dat的字节数
# -1：下载copywrite.rar出错
# -2：解析copywrite.rar出错
# -3：下载qqwry.rar出错
# -4：qqwry.rar文件大小不符合copywrite.rar的数据
# -5：解压缩qqwry.rar出错
# -6：保存到最终文件时出错

import struct
import urllib.request
import zlib
    
def updateQQwry(filename):
    def get_fetcher():
        # no proxy
        proxy = urllib.request.ProxyHandler({})
        # opener
        opener = urllib.request.build_opener(proxy)
        
        def open_url(url):
            # request对象
            req = urllib.request.Request(url)
            ua = ('Mozilla/5.0 (Windows NT 6.1; rv:38.0)'
                  ' Gecko/20100101 Firefox/38.0')
            req.add_header('User-Agent', ua)
            
            try:
                # r是HTTPResponse对象
                r = opener.open(req, timeout=60)
                return r.read()
            except Exception as e:
                return None
        
        return open_url
    
    fetcher = get_fetcher()
    
    # download copywrite.rar
    url = 'http://update.cz88.net/ip/copywrite.rar'
    data = fetcher(url)
    if not data:
        return -1
    
    # extract infomation from copywrite.rar
    if len(data) <= 24 or data[:4] != b'CZIP':
        return -2
    
    version, unknown1, size, unknown2, key = \
        struct.unpack_from('<IIIII', data, 4)
    if unknown1 != 1:
        return -2
    
    # download qqwry.rar
    url = 'http://update.cz88.net/ip/qqwry.rar'
    data = fetcher(url)
    
    if not data:
        return -3
    
    if size != len(data):
        return -4
    
    # decrypt
    head = bytearray(0x200)
    for i in range(0x200):
        key = (key * 0x805 + 1) & 0xff
        head[i] = data[i] ^ key
    data = head + data[0x200:]
    
    # decompress
    try:
        data = zlib.decompress(data)
    except:
        return -5

    # save to file
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        return len(data)
    except:
        return -6

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        ret = updateQQwry(sys.argv[1])
        if ret > 0:
            print('成功更新到%s，%s字节' % 
                  (sys.argv[1], format(ret, ','))
                  )
        else:
            print('更新失败，错误代码：%d' % ret)
    else:
        print('用法：以想要保存的文件名作参数。')
