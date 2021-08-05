import socket
import array
import sys
import struct
import os
import datetime
import time
 
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
 
def checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res = res + (res >> 16)
 
    return ((~res) & 0xffff)
 
def IP_Header( ip_dst, x):
    global ip_ttl
    ip_ver  =   4
    ip_hlen =   5
    ip_tos  =   0
    ip_tlen =   50
    ip_id   =   0
    ip_flag =   0
    ip_fofs =   0
    ip_ttl  =   x
    ip_prot =   1
    ip_cksum=   0
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    ip_src  =   socket.inet_aton(str(ip))
    ip_dst  =   socket.inet_aton(str(ip_dst))
 
    ip_ver_hlen = (ip_ver << 4) + ip_hlen
    ip_flag_offset = (ip_flag << 13) + ip_fofs
    ip_packet   = struct.pack('BBHHHBBH4s4s', ip_ver_hlen, ip_tos, ip_tlen, ip_id, ip_flag_offset, int(ip_ttl), ip_prot, ip_cksum, ip_src, ip_dst)
    return ip_packet
 
def send_icmp_packet(dst_ip, seq, socket, ttl):
    icmp_type = 8 
    icmp_code = 0 
    icmp_chsum= 0 
    icmp_pid  = os.getpid()
    icmp_seq  = seq
 
    chsum_packet = struct.pack('BBHHH', icmp_type, icmp_code, int(icmp_chsum), icmp_pid, icmp_seq)
    data = ("1 2 3 4 5 6 7 8 9 10").encode()
    icmp_checksum = checksum( chsum_packet + data )
    icmp = struct.pack('BBHHH', icmp_type, icmp_code, int(icmp_checksum), icmp_pid, icmp_seq)
    
    icmp_pak = (icmp + data)
    ip_pak = IP_Header( dst_ip, ttl)
    finalize_pak = (ip_pak + icmp_pak)
 
    sock.sendto(finalize_pak, (dst_ip, 0)) 

def recv_packet():
    global src_ip , ttl , code , seq_num
    sock.settimeout(3)
    try:
        raw_pak = sock.recvfrom(65535)[0]
        ip_pak = struct.unpack('!BBHHHBBH4s4s', raw_pak[:20])
        icmp_pak = struct.unpack('!BBHHH', raw_pak[20:28] )
        kk = 'hi'
        src_ip = socket.inet_ntoa(ip_pak[8])
        ttl = ip_pak[5]
        code = icmp_pak[1]
        seq_num = int((hex(icmp_pak[4])), 16)
        if ip != src_ip:
            print(f'{n}\t{src_ip}\t\t{t}')
        return src_ip
    except socket.timeout:
        print(f'{n}   ***')
    
    
try:
    try:
        t = int(sys.argv[2])
    except:
        t = 30

    ip = sys.argv[1]
    try:
        ip = socket.gethostbyname(ip)
    except:
        ip = ip

    n = 1
    print(f'\nTracing route to [{ip}]')
    print('over a maximum of 30 hops:\n')
    while n < t:
        s_time = datetime.datetime.now()
        send_icmp_packet(ip,1,sock,n)
        time.sleep(1)
        src_ip = recv_packet()
        e_time = datetime.datetime.now()
        t = ((s_time - e_time).microseconds / 10000)
        n+=1
        if src_ip == ip:
            print(f'{n-1}\t{ip}\t\t{t}\n')
            break

except KeyboardInterrupt:
    print('\nKeyboard interrupt exception caught')
    
except IndexError:
    print('Please enter a IP Address')
