# coding=utf-8
#
# for Python 3.2+
# 用法：
# q = QQwry()
# q.load_file(filename, loadindex=False)
# q.lookup('8.8.8.8')
#
# 参数loadindex为False时，不加载索引，大约耗内存14MB
# 参数loadindex为True时，加载索引，大约耗内存86MB，搜索性能稍快
# 以上是在Win10, Python 3.4 64bit，qqwry.dat 8.84MB时的数据
# load_file成功返回True，失败返回False
#
# lookup没有找到结果返回None，找到返回一个元组：('国家', '省份')
# lookup使用@functools.lru_cache缓存128条查询结果
#
# q.get_lastone() 返回最后一条数据，最后一条通常为数据版本号
# 没有数据则返回None

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
        self.clear()
        
        # read file
        try:
            f = open(filename, 'br')
            self.data = buffer = f.read() + b'fill'
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
        self.index_count = (index_end - index_begin) // 7 + 1
        
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
            offset = struct.unpack_from('<I', self.data, offset+1)[0]
            offset &= 0xFFFFFF
        p = get_chars(self.data, offset)
        
        return c.decode('gb18030', errors='replace'), \
               p.decode('gb18030', errors='replace')
            
    @functools.lru_cache(maxsize=128, typed=False)
    def lookup(self, ip_str):
        if self.data == None:
            return None
        
        try:
            ip = sum(256**j*int(i) for j,i 
                      in enumerate(ip_str.strip().split('.')[::-1]))
        except:
            return None
        
        if self.index == None:
            r = self.raw_search(ip)
        else:
            r = self.index_search(ip)
        
        return r
        
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
        i = self.__raw_find(ip, 0, self.index_count)
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
        if posi > len(self.index):
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
        
    def get_lastone(self):
        if self.data == None or self.index_count == 0:
            return None
        
        offset = struct.unpack_from('<I', self.data, self.index_end+4)[0]
        offset &= 0xFFFFFF
        
        return self.__get_addr(offset+4)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        fn = 'qqwry.dat'
        q = QQwry()
        q.load_file(fn)
        
        for ipstr in sys.argv[1:]:
            s = q.lookup(ipstr)
            print('%s\n%s' % (ipstr, s))
    else:
        print('请以查询ip作为参数运行')
        