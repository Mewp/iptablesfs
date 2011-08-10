#!/usr/bin/env python2

"""
An iptables filesystem.
An example configuration is in iptablesfs.conf.py. Copy it to /etc.

This filesystem can only be mounted and used by root (unless you have suid on iptables command).

Author: Mewp
License: MIT
"""

import os, stat, errno, re, fuse, imp
from subprocess import Popen, PIPE

if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

tables = ('raw', 'filter', 'nat', 'mangle')
            
files = imp.load_source('files', '/etc/iptablesfs.conf.py').files

class ZeroStat(fuse.Stat):
    def __init__(self):
        self.st_mode = 0
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 0
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 0
        self.st_atime = 0
        self.st_mtime = 0
        self.st_ctime = 0

class IptablesFS(fuse.Fuse):
    
    def __init__(self, *args, **kwargs):
        fuse.Fuse.__init__(self, *args, **kwargs)
        
        self.prepare_chains()
    
    def prepare_chains(self):
        self.chains = {}
        for table in tables:
            self.chains[table] = {}
            for line in Popen(['iptables', '-t' + table, '-S'], stdout=PIPE).communicate()[0].split('\n'):
                m = re.match(r'-([PN]) ([^ ]+)', line)
                if m:
                    self.chains[table][m.group(2)] = {
                        'built-in': m.group(1) == 'P'
                    }

    def get_file(self, table, chain, name):
        data = Popen(['iptables', '-t' + table, '-S' + chain], stdout=PIPE).communicate()[0].split("\n")[:-1]
        if 'exclude' in files[name]:
            data = (line for line in data if not re.search(files[name]['exclude'], line))
        if 'match' in files[name]:
            data = (line for line in data if re.search(files[name]['match'], line))
        if 'hide' in files[name]:
            def hide(line):
                for pattern in files[name]['hide']:
                    line = re.sub(pattern, '', line)
                return line
            data = map(hide, data)
        if 'output_process' in files[name]:
            data = (files[name]['output_process'](self, table, chain, line) for line in data)

        return "\n".join(data) + "\n"

    def get_files(self, table, chain):
        return list(f for f in files.keys() if 'exists' not in files[f] or files[f]['exists'](self, table, chain))

    def getattr(self, path):
        st = ZeroStat()
        path = path[1:].split('/')
        if (len(path) == 1 and path[0] == '') or \
           (len(path) == 1 and path[0] in self.chains) or \
           (len(path) == 2 and path[0] in self.chains and path[1] in self.chains[path[0]]):
            st.st_mode = stat.S_IFDIR | 0755
            st.st_nlink = 2
        elif len(path) == 3 and path[0] in tables and path[1] in self.chains[path[0]] and path[2] in self.get_files(path[0], path[1]):
            st.st_mode = stat.S_IFREG | 0666
            st.st_nlink = 1
            st.st_size = len(self.get_file(*path))
        else:
            return -errno.ENOENT
        return st

    def readdir(self, path, offset):
        if path == '/':
            dirs = self.chains.keys()
        path = path[1:].split('/');
        if len(path) == 1 and path[0] in self.chains:
            dirs = self.chains[path[0]].keys()
        if len(path) == 2 and path[0] in self.chains and path[1] in self.chains[path[0]]:
            dirs = self.get_files(path[0], path[1])
        for r in ['.', '..'] + dirs:
            yield fuse.Direntry(r)

    def mkdir(self, path, mode):
        if path[0] in self.chains and path[1] in self.chains[path[0]]:
            return -errno.EEXIST
        try:
            table, chain = path[1:].split('/');
        except ValueError:
            return -errno.EACCES
        if Popen(['iptables', '-t', table, '-N', chain]).wait():
            return -errno.EACCES
        self.chains[table][chain] = {'built-in': False}
        
    def rmdir(self, path):
        path = path[1:].split('/')
        if len(path) != 2:
            return -errno.EACCES
        if path[0] not in self.chains or path[1] not in self.chains[path[0]]:
            return -errno.ENOENT
        if Popen(['iptables', '-t', path[0], '-F', path[1]]).wait() or \
           Popen(['iptables', '-t', path[0], '-X', path[1]]).wait():
            return -errno.EACCES
        del self.chains[path[0]][path[1]]

    def open(self, path, flags):
        path = path[1:].split("/")
        if len(path) != 3 or path[0] not in self.chains or path[1] not in self.chains[path[0]] or path[2] not in self.get_files(path[0], path[1]):
            return -errno.ENOENT

    def read(self, path, size, offset):
        path = path[1:].split("/")
        if len(path) != 3 or path[0] not in self.chains or path[1] not in self.chains[path[0]] or path[2] not in self.get_files(path[0], path[1]):
            return -errno.ENOENT
        data = self.get_file(*path)
        slen = len(data)
        if offset < slen:
            if offset + size > slen:
                size = slen - offset
            buf = data[offset:offset+size]
        else:
            buf = ''
        return buf
        
    def write_process_line(self, table, chain, name, line, **options):
        options.update(files[name])
        if 'prepend' in options:
            line = options['prepend'] + ' ' + line
        if 'append' in options:
            line = line + ' ' + options['append']
        if 'chain_option' in options:
            chain_option = options['chain_option']
        elif re.match(r'^[0-9]', line):
            chain_option = 'I'
        else:
            chain_option = 'A'
        
        line = 'iptables -t' + table + ' -' + chain_option + ' ' + chain + ' ' + line
        if 'process' in options:
                line = options['process'](self, table, chain, line)
        return line

    def write(self, path, buf, offset):
        path = path[1:].split('/')
        for line in buf.split("\n"):
            if len(line) == 0: continue
            line = self.write_process_line(path[0], path[1], path[2], line)
            
            Popen(line, shell=True)
        return len(buf)

    def truncate(self, path, len):
        if len == 0 and path.endswith('rules'):
            path = path[1:].split('/')
            Popen(['iptables', '-t', path[0], '-F', path[1]]).communicate()
        elif len == 0:
            table, chain, name = path[1:].split('/')
            for line in self.get_file(table, chain, name).split("\n"):
                line = self.write_process_line(table, chain, name, line, chain_option='D')
                print line
                Popen(line, shell=True)

if __name__ == '__main__':
    server = IptablesFS(version="%prog " + fuse.__version__, dash_s_do='setsingle')
    server.parse(errex=1)
    server.main()
