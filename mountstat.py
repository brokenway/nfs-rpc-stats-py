#!/usr/bin/env python
# -*- python-mode -*-
"""Parse /proc/self/mountstats and display it in human readable form
"""

__copyright__ = """
Copyright (C) 2005, Chuck Lever <cel@netapp.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""

import sys, os, time, optparse

__maintainers__ = ['Blake Golliher', 'Geoffrey Golliher']

Mountstats_version = '0.2'

def difference(x, y):
  """Used for a map() function
  """
  return x - y

class DeviceData:
  """DeviceData objects provide methods for parsing and displaying
  data for a single mount grabbed from /proc/self/mountstats
  """
  def __init__(self):
    self.__nfs_data = dict()
    self.__rpc_data = dict()
    self.__rpc_data['ops'] = []

  def __parse_nfs_line(self, words):
    if words[0] == 'device':
      self.__nfs_data['export'] = words[1]
      self.__nfs_data['mountpoint'] = words[4]
      self.__nfs_data['fstype'] = words[7]
      if words[7].find('nfs') != -1 and len(words) > 8:
        self.__nfs_data['statvers'] = words[8]
    elif words[0] == 'age:':
      self.__nfs_data['age'] = long(words[1])
    elif words[0] == 'opts:':
      self.__nfs_data['mountoptions'] = ''.join(words[1:]).split(',')
    elif words[0] == 'caps:':
      self.__nfs_data['servercapabilities'] = ''.join(words[1:]).split(',')
    elif words[0] == 'nfsv4:':
      self.__nfs_data['nfsv4flags'] = ''.join(words[1:]).split(',')
    elif words[0] == 'sec:':
      keys = ''.join(words[1:]).split(',')
      self.__nfs_data['flavor'] = int(keys[0].split('=')[1])
      self.__nfs_data['pseudoflavor'] = 0
      if self.__nfs_data['flavor'] == 6:
        self.__nfs_data['pseudoflavor'] = int(keys[1].split('=')[1])
    elif words[0] == 'events:':
      self.__nfs_data['inoderevalidates'] = int(words[1])
      self.__nfs_data['dentryrevalidates'] = int(words[2])
      self.__nfs_data['datainvalidates'] = int(words[3])
      self.__nfs_data['attrinvalidates'] = int(words[4])
      self.__nfs_data['syncinodes'] = int(words[5])
      self.__nfs_data['vfsopen'] = int(words[6])
      self.__nfs_data['vfslookup'] = int(words[7])
      self.__nfs_data['vfspermission'] = int(words[8])
      self.__nfs_data['vfsreadpage'] = int(words[9])
      self.__nfs_data['vfsreadpages'] = int(words[10])
      self.__nfs_data['vfswritepage'] = int(words[11])
      self.__nfs_data['vfswritepages'] = int(words[12])
      self.__nfs_data['vfsreaddir'] = int(words[13])
      self.__nfs_data['vfsflush'] = int(words[14])
      self.__nfs_data['vfsfsync'] = int(words[15])
      self.__nfs_data['vfslock'] = int(words[16])
      self.__nfs_data['vfsrelease'] = int(words[17])
      self.__nfs_data['setattrtrunc'] = int(words[18])
      self.__nfs_data['extendwrite'] = int(words[19])
      self.__nfs_data['sillyrenames'] = int(words[20])
      self.__nfs_data['shortreads'] = int(words[21])
      self.__nfs_data['shortwrites'] = int(words[22])
      self.__nfs_data['delay'] = int(words[23])
    elif words[0] == 'bytes:':
      self.__nfs_data['normalreadbytes'] = long(words[1])
      self.__nfs_data['normalwritebytes'] = long(words[2])
      self.__nfs_data['directreadbytes'] = long(words[3])
      self.__nfs_data['directwritebytes'] = long(words[4])
      self.__nfs_data['serverreadbytes'] = long(words[5])
      self.__nfs_data['serverwritebytes'] = long(words[6])

  def __parse_rpc_line(self, words):
    if words[0] == 'RPC':
      self.__rpc_data['statsvers'] = float(words[3])
      self.__rpc_data['programversion'] = words[5]
    elif words[0] == 'xprt:':
      self.__rpc_data['protocol'] = words[1]
      if words[1] == 'udp':
        self.__rpc_data['port'] = int(words[2])
        self.__rpc_data['bind_count'] = int(words[3])
        self.__rpc_data['rpcsends'] = int(words[4])
        self.__rpc_data['rpcreceives'] = int(words[5])
        self.__rpc_data['badxids'] = int(words[6])
        self.__rpc_data['backlogutil'] = int(words[7])
      elif words[1] == 'tcp':
        self.__rpc_data['port'] = words[2]
        self.__rpc_data['bind_count'] = int(words[3])
        self.__rpc_data['connect_count'] = int(words[4])
        self.__rpc_data['connect_time'] = int(words[5])
        self.__rpc_data['idle_time'] = int(words[6])
        self.__rpc_data['rpcsends'] = int(words[7])
        self.__rpc_data['rpcreceives'] = int(words[8])
        self.__rpc_data['badxids'] = int(words[9])
        self.__rpc_data['backlogutil'] = int(words[10])
    elif words[0] == 'per-op':
      self.__rpc_data['per-op'] = words
    else:
      op = words[0][:-1]
      self.__rpc_data['ops'] += [op]
      self.__rpc_data[op] = [long(word) for word in words[1:]]

  def parse_stats(self, lines):
    """Turn a list of lines from a mount stat file into a 
    dictionary full of stats, keyed by name
    """
    found = False
    for line in lines:
      words = line.split()
      if len(words) == 0:
        continue
      if (not found and words[0] != 'RPC'):
        self.__parse_nfs_line(words)
        continue

      found = True
      self.__parse_rpc_line(words)

  def is_nfs_mountpoint(self):
    """Return True if this is an NFS or NFSv4 mountpoint,
    otherwise return False
    """
    if self.__nfs_data['fstype'] == 'nfs':
      return True
    elif self.__nfs_data['fstype'] == 'nfs4':
      return True
    return False

  # Read: GETATTR LOOKUP ACCESS READLINK READ READDIR READDIRPLUS FSSTAT FSINFO PATHCONF
  # Write: SETATTR WRITE CREATE MKDIR MKNOD RENAME LINK COMMIT
  def calc_other_ops(self, sample_time, others):
    others_dict = {}
    for s in others:
      others_dict[s] = []
      avg_rtt = 0.00
      avg_exe = 0.00
      rpc_stats = self.__rpc_data[s]
      ops = float(rpc_stats[0])
      rtt = float(rpc_stats[6])
      exe = float(rpc_stats[7])
      ops_per_sec = ops / sample_time
      others_dict[s].append(('ops_per_sec', ops_per_sec))
      if ops != 0:
        avg_rtt = rtt / ops
        avg_exe = exe / ops
      others_dict[s].append(('avg_rtt', avg_rtt))
      others_dict[s].append(('avg_exe', avg_exe))
    return others_dict

  def build_read_stats(self, sample_time, full=False):
    # reads:  ops/s, Kb/s, avg rtt, and avg exe
    read_avg_rtt = 0.00
    read_avg_exe = 0.00
    others_list = []
    read_rpc_stats = self.__rpc_data['READ']
    read_ops = float(read_rpc_stats[0])
    read_kilobytes = float(self.__nfs_data['serverreadbytes']) / 1024
    read_rtt = float(read_rpc_stats[6])
    read_exe = float(read_rpc_stats[7])
    read_ops_per_sec = read_ops / sample_time
    read_kb_per_sec = read_kilobytes / sample_time
    if read_ops != 0:
      read_avg_rtt = read_rtt / read_ops
      read_avg_exe = read_exe / read_ops
    read_list = [('read_ops_per_sec', read_ops_per_sec),
                 ('read_kb_per_sec', read_kb_per_sec),
                 ('read_avg_rtt', read_avg_rtt),
                 ('read_avg_exe', read_avg_exe)]
    if full:
      others_list = [(k, v) for k, v in self.calc_other_ops(sample_time,
          ops_maps['READ']).iteritems()]

    return read_list + others_list

  def build_write_stats(self, sample_time, full=False):
    # writes:  ops/s, Kb/s, avg rtt, and avg exe
    write_avg_rtt = 0.00
    write_avg_exe = 0.00
    others_list = []
    write_rpc_stats = self.__rpc_data['WRITE']
    write_ops = float(write_rpc_stats[0])
    write_kilobytes = float(self.__nfs_data['serverwritebytes']) / 1024
    write_rtt = float(write_rpc_stats[6])
    write_exe = float(write_rpc_stats[7])
    write_ops_per_sec = write_ops / sample_time
    write_kb_per_sec = write_kilobytes / sample_time
    if write_ops != 0:
      write_avg_rtt = write_rtt / write_ops
      write_avg_exe = write_exe / write_ops
    write_list = [('write_ops_per_sec', write_ops_per_sec),
                  ('write_kb_per_sec', write_kb_per_sec),
                  ('write_avg_rtt', write_avg_rtt),
                  ('write_avg_exe', write_avg_exe)]
    if full:
      others_list = [(k, v) for k, v in self.calc_other_ops(sample_time,
          ops_maps['WRITE']).iteritems()]

    return write_list + others_list
  
  def display_iostats(self, sample_time, options):
    """Display NFS and RPC stats in an iostat-like way
    """
    if not options.csv_on:
      return self.display_iostats_human(sample_time)
    sends = float(self.__rpc_data['rpcsends'])
    if sample_time == 0:
      sample_time = float(self.__nfs_data['age'])
    ops_backlog = 0.00
    if sends !=0:
      ops_backlog = (float(
          self.__rpc_data['backlogutil']) / sends) / sample_time
    ops_per_sec = sends / sample_time
    read_full = options.read_stats_on or options.all_stats_on
    write_full = options.write_stats_on or options.all_stats_on
    stats = [('export', self.__nfs_data['export']),
             ('mountpoint', self.__nfs_data['mountpoint']),
	     ('ops_per_sec', ops_per_sec), ('ops_backlog', ops_backlog)]
    stats += self.build_read_stats(sample_time, read_full )
    stats += self.build_write_stats(sample_time, write_full )
    self.format_iostats_display(options, stats)

  def format_iostats_display(self, options, stats):
    # Creating a dict here for readability: stats[0][1] is not very helpful.
    stats_dict = dict(stats)
    oline_pre = ''
    oline_others_pre = ''
    oline_others = ''
    if options.csv_on:
      if options.csv_headers_on:
        # List comprehension madness begin!!
        oline_pre = ','.join([k for k,v in stats
	    if k not in ops_maps['READ'] and k not in ops_maps['WRITE']])
        oline_others_pre = ','.join(["%s_%s" % (k, key) for k,v in stats
	    if k in ops_maps['READ'] or k in ops_maps['WRITE']
	    for key, val in v])
	print "%s,%s" % (oline_pre, oline_others_pre)
      oline_others = ','.join(
          ['%.5f' % val for k,v in stats
	   if k in ops_maps['READ'] or k in ops_maps['WRITE']
	   for key,val in v])
      oline = '%s,%s,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f,%.5f' % (
          stats_dict['export'], stats_dict['mountpoint'],
          stats_dict['ops_per_sec'], stats_dict['ops_backlog'],
	  stats_dict['read_ops_per_sec'], stats_dict['read_kb_per_sec'],
          stats_dict['read_avg_rtt'], stats_dict['read_avg_exe'],
	  stats_dict['write_ops_per_sec'], stats_dict['write_kb_per_sec'],
          stats_dict['write_avg_rtt'], stats_dict['write_avg_exe'])
    else:
      oline_pre = ("Call Name :: Total Op / s :: retransmit rate :: bytes sent"
                  "(kbits) :: bytes received (kbits) :: rtt (ms) :: avg exe (ms)")

    if oline_others:
      print "%s,%s" % (oline, oline_others)
    else:
      print oline

  # TODO(geoffrey): Refactor this into display_iostats().
  # Call Name :: Total Op / s :: retransmit rate :: bytes sent (kbits) :: bytes received (kbits) :: rtt (ms) :: avg exe (ms)
  def display_iostats_human(self, sample_time):
    """Display NFS and RPC stats in an iostat-like way
    """
    sends = float(self.__rpc_data['rpcsends'])
    if sample_time == 0:
      sample_time = float(self.__nfs_data['age'])

    print
    print '%s mounted on %s:' % \
      (self.__nfs_data['export'], self.__nfs_data['mountpoint'])

    print '\top/s\trpc bklog'
    print '\t%.2f' % (sends / sample_time), 
    if sends != 0:
      print '\t%.2f' % \
        ((float(self.__rpc_data['backlogutil']) / sends) / sample_time)
    else:
      print '\t0.00'

    # reads:  ops/s, Kb/s, avg rtt, and avg exe
    # XXX: include avg xfer size and retransmits?
    read_rpc_stats = self.__rpc_data['READ']
    ops = float(read_rpc_stats[0])
    kilobytes = float(self.__nfs_data['serverreadbytes']) / 1024
    rtt = float(read_rpc_stats[6])
    exe = float(read_rpc_stats[7])

    print '\treads:\tops/s\t\tKb/s\t\tavg RTT (ms)\tavg exe (ms)'
    print '\t\t%.2f' % (ops / sample_time),
    print '\t\t%.2f' % (kilobytes / sample_time),
    if ops != 0:
      print '\t\t%.2f' % (rtt / ops),
      print '\t\t%.2f' % (exe / ops)
    else:
      print '\t\t0.00',
      print '\t\t0.00'

    # writes:  ops/s, Kb/s, avg rtt, and avg exe
    # XXX: include avg xfer size and retransmits?
    write_rpc_stats = self.__rpc_data['WRITE']
    ops = float(write_rpc_stats[0])
    kilobytes = float(self.__nfs_data['serverwritebytes']) / 1024
    rtt = float(write_rpc_stats[6])
    exe = float(write_rpc_stats[7])

    print '\twrites:\tops/s\t\tKb/s\t\tavg RTT (ms)\tavg exe (ms)'
    print '\t\t%.2f' % (ops / sample_time),
    print '\t\t%.2f' % (kilobytes / sample_time),
    if ops != 0:
      print '\t\t%.2f' % (rtt / ops),
      print '\t\t%.2f' % (exe / ops)
    else:
      print '\t\t0.00',
      print '\t\t0.00'

def parse_stats_file(filename):
  """pop the contents of a mountstats file into a dictionary,
  keyed by mount point.  each value object is a list of the
  lines in the mountstats file corresponding to the mount
  point named in the key.
  """
  ms_dict = {} 
  key = ''

  f = file(filename)
  for line in f.readlines():
    words = line.split()
    if len(words) == 0:
      continue
    if words[0] == 'device':
      key = words[4]
      new = [ line.strip() ]
    else:
      new += [ line.strip() ]
    ms_dict[key] = new
  f.close

  return ms_dict

def print_iostat_summary(new, devices, time, options):
  for device in devices:
    stats = DeviceData()
    stats.parse_stats(new[device])
    stats.display_iostats(time, options)

def iostat_command(options, args):
  """iostat-like command for NFS mount points
  """
  mountstats = parse_stats_file(options.mountstats_file)
  devices = []
  sample_time = 0
  # Checking if arg(s) was passed indicating particular mountpoint(s) to check.
  for arg in args:
    if arg in mountstats:
      devices += [arg]
  if len(devices) > 0:
    check = []
    for device in devices:
      stats = DeviceData()
      stats.parse_stats(mountstats[device])
      if stats.is_nfs_mountpoint():
        check += [device]
      devices = check
  else:
    for device, descr in mountstats.iteritems():
      stats = DeviceData()
      stats.parse_stats(descr)
      if stats.is_nfs_mountpoint():
        devices += [device]
  if len(devices) == 0:
    print 'No NFS mount points were found'
    return
  
  print_iostat_summary(mountstats, devices, sample_time, options)
  return

def handle_options():
  parser = optparse.OptionParser("Usage: %prog [options]",
      version="%prog .01")
  parser.add_option("-c", "--csv", action="store_true", dest="csv_on",
                    help="Specify csv output.", default=False)
  parser.add_option("-k", "--csv_headers", action="store_true", dest="csv_headers_on",
                    help="Specify csv output plus headers.", default=False)
  parser.add_option("-a", "--all_stats", action="store_true",
                    dest="all_stats_on",
                    help="Get all other stats from I/O ops.",
		    default=False)
  parser.add_option("-r", "--read_stats", action="store_true",
                    dest="read_stats_on",
                    help="Get all other stats from Read I/O ops.",
		    default=False)
  parser.add_option("-w", "--write_stats", action="store_true",
                    dest="write_stats_on",
                    help="Get all other stats from Write I/O ops.",
		    default=False)
  parser.add_option("-f", "--mountstats_file", dest="mountstats_file",
                    help="Get all other stats from Write I/O ops.",
		    default='/proc/self/mountstats')

  return parser.parse_args()
#
# Main
#

ops_maps = {'READ': ['GETATTR', 'LOOKUP', 'ACCESS', 'READLINK',
                     'READDIR', 'READDIRPLUS', 'FSSTAT', 'FSINFO', 'PATHCONF'],
            'WRITE': ['SETATTR', 'CREATE', 'MKDIR', 'MKNOD', 'RENAME',
	              'LINK', 'COMMIT']
           }
options, args = handle_options()
iostat_command(options, args)
sys.exit(0)
