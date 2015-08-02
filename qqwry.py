# for Python 3.2+
#
# 用法：
# q = QQwry()
# q.load_file(filename, loadindex=False)
# q.search('8.8.8.8')
#
# loadindex为False时，不加载索引，大约耗内存14MB
# loadindex为True时，加载索引，大约耗内存86MB，搜索性能稍快
# 以上是在Win10, Python 3.4 64bit，qqwry.dat 8.84MB时的数据
# load_file成功返回True，失败返回False
#
# search没有找到结果返回None，找到返回一个元组：('国家', '省份')
#
# 使用@functools.lru_cache缓存128条最近查询的结果

import struct
import bisect
import functools

__all__ = ('QQwry')

class ip_fragment:
    __slots__ = ('begin', 'end', 'offset')
    
    def __init__(self, begin, end=0, offset=0):
        self.begin = begin
        self.end = end
        self.offset = offset
    
    def __lt__(self, other):
        return self.begin < other.begin

class QQwry:
    def __init__(self):
        self.clear()
        
    def clear(self):
        self.index = None
        self.data = None
        self.index_begin = -1
        self.index_end = -1
        self.index_count = -1
        
    def load_file(self, filename, loadindex=False):
        # read file
        try:
            f = open(filename, 'br')
            self.data = buffer = f.read()
        except:
            print('qqwry.dat load failed')
            return False
        
        # index range
        index_begin, index_end = struct.unpack_from('<II', buffer, 0)        
        if (index_end - index_begin) % 7 != 0:
            print('qqwry.dat index error')
            return False
        
        self.index_begin = index_begin
        self.index_end = index_end
        self.index_count = (index_end - index_begin) // 7
        
        if not loadindex:
            print('qqwry.dat %s bytes.' %  format(len(buffer),','))
            return True

        # load index
        self.index = list()
        
        for i in range(self.index_count):
            ip_begin = struct.unpack_from('<I', buffer, 
                                    index_begin + i*7)[0]
            offset = struct.unpack_from('<I', buffer,
                                    index_begin + i*7 + 4)[0]
            offset &= 0xffffff
            
            # load ip_end
            ip_end = struct.unpack_from('<I', buffer, offset)[0]
            
            f = ip_fragment(ip_begin, ip_end, offset+4)
            self.index.append(f)

        print('qqwry.dat %s bytes, %d fragments.' % 
              (format(len(buffer),','), len(self.index))
               )
        return True
        
    def __get_addr(self, offset):
        
        # get C null-terminated string
        def get_chars(buffer, offset):
            count = 0
            maxposi = len(buffer) - offset
            while count < maxposi and \
                  buffer[offset+count] != 0:
                count += 1
            return buffer[offset:offset+count]
        
        # mode 0x01, full jump
        mode = struct.unpack_from('b', self.data, offset)[0]
        if mode == 1:
            offset = struct.unpack_from('<I', self.data, offset+1)[0]
            offset = offset & 0xFFFFFF
            mode = struct.unpack_from('b', self.data, offset)[0]
        
        # country
        if mode == 2:
            off1 = struct.unpack_from('<I', self.data, offset+1)[0]
            off1 &= 0xFFFFFF
            c = get_chars(self.data, off1)
            offset += 4
        else:
            c = get_chars(self.data, offset)
            offset += len(c) + 1

        # province
        mode = struct.unpack_from('b', self.data, offset)[0]
        if mode == 2:
            off1 = struct.unpack_from('<I', self.data, offset+1)[0]
            off1 &= 0xFFFFFF
            p = get_chars(self.data, off1)
        else:
            p = get_chars(self.data, offset)
            
        return c, p
            
    @functools.lru_cache(maxsize=128, typed=False)
    def search(self, ip_str):
        ip = sum(256**j*int(i) for j,i 
                  in enumerate(ip_str.strip().split('.')[::-1]))
        
        if self.index == None:
            r = self.raw_search(ip)
        else:
            r = self.index_search(ip)
        
        if r == None:
            return None

        return r[0].decode('gb18030'), r[1].decode('gb18030')
        
    def __raw_find(self, ip, l, r):
        if r - l <= 1:
            return l

        m = (l + r) // 2
        offset = self.index_begin + m * 7
        new_ip = struct.unpack_from('<I', self.data, offset)[0]

        if ip < new_ip:
            return self.__raw_find(ip, l, m)
        else:
            return self.__raw_find(ip, m, r)
    
    def raw_search(self, ip):
        i = self.__raw_find(ip, 0, self.index_count - 1)
        offset = self.index_begin + 7 * i
        
        ip_begin = struct.unpack_from('<I', self.data, offset)[0]
        
        offset = struct.unpack_from('<I', self.data, offset+4)[0]
        offset &= 0xFFFFFF
        
        ip_end = struct.unpack_from('<I', self.data, offset)[0]
        
        if ip_begin <= ip <= ip_end:
            return self.__get_addr(offset+4)
        
        return None
    
    def index_search(self, ip):
        sf = ip_fragment(ip)
        posi = bisect.bisect_left(self.index, sf)
        if posi >= len(self.index):
            return None
        
        result = None
        
        # previous fragement
        if posi > 0:
            f = self.index[posi-1]
            if f.begin <= ip <= f.end:
                result = f
    
        # ip == current.begin
        if result == None and \
           posi != len(self.index) and \
           self.index[posi].begin == ip:
            result = self.index[posi]
        
        if result != None:
            return self.__get_addr(result.offset)
        else:
            return None
        
def test():
    fn = 'qqwry.dat'
    
    q1 = QQwry()
    q1.load_file(fn, True)
    
    q2 = QQwry()
    q2.load_file(fn, False)
    
    ips = '''
    0.0.0.0 1.1.1.1 255.255.255.255 255.255.255.333 8.8.8.7 8.8.8.8
    115.92.25.1 118.99.28.80 180.158.208.229 113.62.100.36 192.168.11.90 58.221.42.157 106.123.228.101 175.16.168.192 123.138.116.198 121.201.24.246
    121.201.24.246 218.92.226.42 123.124.230.102 103.19.151.1 60.21.209.108 222.76.102.19 174.128.255.227 115.60.183.18 222.178.157.95 192.168.0.104
    115.231.16.161 118.99.28.80 60.21.209.108 58.221.42.157 125.211.218.45 8.8.8.8 113.0.112.55 121.201.24.246 180.158.208.229 103.237.197.1
    125.211.218.45 116.255.135.61 121.201.24.246 23.234.25.12 117.41.235.100 121.41.74.174 222.76.102.19 120.244.67.1 118.99.28.80 180.158.208.229
    104.216.23.180 222.186.12.46 121.201.24.246 183.60.107.217 180.158.208.229 118.193.162.234 117.41.235.100 113.62.100.36 60.21.209.108 122.5.249.248
    117.41.235.100 180.158.208.229 58.34.97.67 121.201.24.246 175.44.8.152 60.21.209.108 101.220.26.1 11.123.254.1 106.50.224.1 58.221.42.157
    123.158.113.4 60.21.209.108 174.128.255.231 10.42.7.217 117.41.235.100 111.207.170.91 121.201.24.246 103.63.251.255 183.22.114.41 139.170.105.1
    60.21.209.108 106.53.124.1 121.201.24.246 49.89.177.27 61.145.118.16 101.226.168.250 174.128.255.227 222.76.102.19 115.60.183.18 180.158.208.229
    180.158.208.229 121.201.24.246 60.21.209.108 101.83.219.43 105.83.25.1 107.95.133.1 106.208.191.1 117.165.60.242 222.76.102.19 117.41.235.100
    60.21.209.108 180.158.208.229 222.76.102.19 188.143.234.155 119.100.252.190 222.136.82.153 116.255.135.61 125.211.218.45 121.201.24.246 174.128.255.230
    219.145.171.44 118.99.28.80 121.201.24.246 103.44.145.243 117.41.235.100 216.99.158.141 106.152.254.1 222.76.102.19 125.211.218.45 60.21.209.108
    222.76.102.19 58.51.150.40 60.21.209.108 121.201.24.246 117.41.235.100 192.168.0.104 125.211.218.45 174.128.255.227 211.159.139.230 180.158.208.229
    111.207.170.91 174.128.255.227 222.186.12.46 60.21.209.108 121.201.24.246 118.99.28.80 110.179.124.241 117.41.235.100 1.50.31.4 222.76.102.19
    121.201.24.246 220.170.79.231 180.158.208.229 121.18.165.1 107.74.60.1 118.99.28.80 60.21.209.108 23.234.25.12 192.168.11.90 103.44.145.243
    '''
    ips = [i.strip() for i in ips.split()]
    for ip in ips:
        r1 = q1.search(ip)
        r2 = q2.search(ip)
        print(ip, r1)
        if r1 != r2:
            print('errorrrrrrrrrrrrrrrrrrrrrrrrrr')

if __name__ == '__main__':
    #test()

    import sys
    if len(sys.argv) > 1:
        fn = 'qqwry.dat'
        q = QQwry()
        q.load_file(fn)
        
        ipstr = sys.argv[1]
        s = q.search(ipstr)
        print(s)
    else:
        print('请以查询ip作为参数运行')
        