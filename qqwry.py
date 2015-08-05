# coding=utf-8
#
# for Python 3.0+
# 来自 https://github.com/animalize/qqwry-python3
#
# 用法：
# q = QQwry()
# q.load_file(filename, loadindex=False)
# q.lookup('8.8.8.8')
#
# q.load_file(filename, loadindex=False)函数:
# 参数loadindex为False时，不加载索引，进程耗内存13.2MB
# 参数loadindex为True时，加载索引，进程耗内存18.8MB
# 后者比前者查找更快（3.1万次/秒，6.9万次/秒），但加载文件稍慢
# 以上是在i3 3.6GHz, Win10, Python 3.4 64bit，qqwry.dat 8.84MB时的数据
# 成功返回True，失败返回False
#
# q.lookup('8.8.8.8')函数:
# 没有找到结果返回一个None
# 找到则返回一个含有两个字符串的元组：('国家', '省份')
#
# q.get_lastone()函数:
# 返回最后一条数据，最后一条通常为数据版本号
# 没有数据则返回None
#
# q.is_loaded()函数:
# 是否已加载数据，返回True或False
#
# q.clear()函数:
# 清空已加载的qqwry.dat
# 再次调用load_file时不必执行q.clear()

import array
import bisect

__all__ = ('QQwry')
    
def int3(data, offset):
    return data[offset] + (data[offset+1] << 8) + \
           (data[offset+2] << 16)

def int4(data, offset):
    return data[offset] + (data[offset+1] << 8) + \
           (data[offset+2] << 16) + (data[offset+3] << 24)

class QQwry:
    def __init__(self):
        self.clear()
        
    def clear(self):
        self.idx1 = None
        self.idx2 = None
        self.idxo = None
        
        self.data = None
        self.index_begin = -1
        self.index_end = -1
        self.index_count = -1
        
    def load_file(self, filename, loadindex=False):
        self.clear()
        
        # read file
        with open(filename, 'br') as f:
            self.data = buffer = f.read()
        
        if self.data == None:
            print('%s load failed' % filename)
            self.clear()
            return False
        
        if len(buffer) < 8:
            print('%s load failed, file only %d bytes' % 
                  (filename, len(buffer))
                  )
            self.clear()
            return False            
        
        # index range
        index_begin = int4(buffer, 0)
        index_end = int4(buffer, 4)
        if index_begin > index_end or \
           (index_end - index_begin) % 7 != 0 or \
           index_end >= len(buffer):
            print('%s index error' % filename)
            self.clear()
            return False
        
        self.index_begin = index_begin
        self.index_end = index_end
        self.index_count = (index_end - index_begin) // 7 + 1
        
        if not loadindex:
            print('%s %s bytes, %d segments. without index.' %
                  (filename, format(len(buffer),','), self.index_count)
                 )
            return True

        # load index
        self.idx1 = array.array('L')
        self.idx2 = array.array('L')
        self.idxo = array.array('L')
        
        try:
            for i in range(self.index_count):
                ip_begin = int4(buffer, index_begin + i*7)
                offset = int3(buffer, index_begin + i*7 + 4)
                
                # load ip_end
                ip_end = int4(buffer, offset)
                
                self.idx1.append(ip_begin)
                self.idx2.append(ip_end)
                self.idxo.append(offset+4)
        except:
            print('%s load index error' % filename)
            self.clear()
            return False

        print('%s %s bytes, %d segments. with index.' % 
              (filename, format(len(buffer),','), len(self.idx1))
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
        mode = self.data[offset]
        if mode == 1:
            offset = int3(self.data, offset+1)
            mode = self.data[offset]
        
        # country
        if mode == 2:
            off1 = int3(self.data, offset+1)
            c = get_chars(self.data, off1)
            offset += 4
        else:
            c = get_chars(self.data, offset)
            offset += len(c) + 1

        # province
        if self.data[offset] == 2:
            offset = int3(self.data, offset+1)
        p = get_chars(self.data, offset)
        
        return c.decode('gb18030', errors='replace'), \
               p.decode('gb18030', errors='replace')
            
    def lookup(self, ip_str):
        try:
            ip = sum(256**j*int(i) for j,i 
                      in enumerate(ip_str.strip().split('.')[::-1]))

            if self.idx1 == None:
                return self.raw_search(ip)
            else:
                return self.index_search(ip)
        except:
            return None
        
    def __raw_find(self, ip, l, r):
        while r - l > 1:
            m = (l + r) // 2
            offset = self.index_begin + m * 7
            new_ip = int4(self.data, offset)
    
            if ip < new_ip:
                r = m
            else:
                l = m
        return l
    
    def raw_search(self, ip):
        i = self.__raw_find(ip, 0, self.index_count)
        offset = self.index_begin + 7 * i
        ip_begin = int4(self.data, offset)
        
        offset = int3(self.data, offset+4)
        ip_end = int4(self.data, offset)
        
        if ip_begin <= ip <= ip_end:
            return self.__get_addr(offset+4)
        
        return None
    
    def index_search(self, ip):
        posi = bisect.bisect_left(self.idx1, ip)
        
        result = -1
        
        # previous fragement
        if posi > 0:
            if self.idx1[posi-1] <= ip <= self.idx2[posi-1]:
                result = posi - 1
    
        # ip == current.begin
        if result == -1 and \
           posi != len(self.idx1) and \
           self.idx1[posi] == ip:
            result = posi
        
        if result != -1:
            return self.__get_addr(self.idxo[result])
        else:
            return None
        
    def is_loaded(self):
        return self.index_begin != -1
        
    def get_lastone(self):
        try:
            offset = int3(self.data, self.index_end+4)
            return self.__get_addr(offset+4)
        except:
            return None

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
        