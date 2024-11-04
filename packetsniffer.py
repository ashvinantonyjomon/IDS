import socket
import struct
import textwrap
import csv


TAB_1='\t -'
TAB_2='\t\t -'
TAB_3='\t\t\t -'
TAB_4='\t\t\t\t -'


DATA_TAB_1='\t -'
DATA_TAB_2='\t\t -'
DATA_TAB_3='\t\t\t -'
DATA_TAB_4='\t\t\t\t -'


#creating csv file

def init_csv():
    fname="cap_packs.csv"
    writ=csv.writer(open(fname,'w',buffering=1),delimiter=',')
    header=["src_mac","dest_mac","eth_proto","src_ip","dst_ip","protocol","src_port","dst_port","packet"]
    writ.writerow(header)
init_csv()

def update_csv(row):
    fname="cap_packs.csv"
    writ=csv.writer(open(fname,'a',buffering=1),delimiter=',')
    writ.writerow(row)




def main():
    conn=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


    while True:
        raw_data, addr = conn.recvfrom(65536) #buffersize
        dest_mac,src_mac,eth_proto,data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + 'Destiantion: {} , Source: {} , Protocol: {}'.format(dest_mac,src_mac,eth_proto))


        src_ip,dst_ip,src_port,dst_port,proto=None,None,None,None,None 
        row=[src_mac,dest_mac,eth_proto,"" ,"", "", "", "",""]
        update_csv(row)




        #IF ETH IS 8 ITS IPV4
        if eth_proto==8:
            (version,header_length,ttl,proto,src,target,data)=ipv4_packet(data)
            print(TAB_1+'IPv4 Packet:')
            print(TAB_2+ 'Version: {} ,Header Length: {}, TTL: {}'.format(version,header_length,ttl))
            print(TAB_2 + 'Protocol: {}, Source: {} , Target: {}'.format(proto,src,target))
            row=[" "," ",proto,src,target,proto," "," ", " " ]
            update_csv(row)



            protocol = proto

                #ICMP
            if proto==1:#cause in the packet the protocol part 1 means icmp different num for diff protocols
                icmp_type,code,checksum,data=icmp_packet(data)
                print(TAB_1 + 'ICMP PACKET: ')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type,code,checksum))
                print(TAB_2 + 'DATA: ')
                print(format_multi_line(DATA_TAB_3,data))
                row=["","",proto,"","",proto,"","",data]
                update_csv(row)

                #TCP
            elif proto==6:
                (src_prot,dest_prot,sequence,acknowldegement,offset_reserved_flag,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data)=tcp_segment(data)
                print(TAB_1+'TCP segemnt: ')
                print(TAB_2+'Source port: {} , Destination_port: {}'.format(src_prot,dest_prot))
                print(TAB_2 + 'Sequence :{}, Acknowledgement: {}'.format(sequence,acknowldegement))
                print(TAB_2+'Flag:')
                print(TAB_3+'URG:{},ACK:{},PSH:{},RST:{},SYN:{},FIN:{}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                print(TAB_2+'DATA:')
                print(format_multi_line(DATA_TAB_3,data))
                row=["","",proto,src_prot,dest_prot,proto,"","",data]
                update_csv(row)

                #UDP
            elif proto==17:
                src_port,dest_port,length,data=udp_segment(data)
                print(TAB_1+'udp_SEGMENT')
                print(TAB_2+'Source port:{},Destination Port:{},Length:{}'.format(src_port,dest_port,length))
                row=["","",proto,"","",proto,src_port,dest_port,data]
                update_csv(row)
            
            else:
                print(TAB_1+'DATA: ')
                print(format_multi_line(DATA_TAB_2,data))
                
        else:
            print(TAB_1+'DATA: ')
            print(format_multi_line(DATA_TAB_1,data))


        #print(f"src_ip:{src_ip},dst_ip:{dst_ip},src_port:{src_port},dst_port:{dst_port},protocol:{protocol}")

        

    
#unpack the ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto = struct.unpack('! 6s 6s H', data[:14])#how bytes are represented
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto), data[14:]


#formating mac(AA:BB:CC...)

def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()



#unpacks IPv4 packets
def ipv4_packet(data):
    version_header_length= data[0]
    version = version_header_length >> 4 #bit shifting 4 bytes
    header_length=(version_header_length&15)*4
    ttl,proto,src,target=struct.unpack('!8xBB2x4s4s', data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]


#returning formated IPv4 adress
def ipv4(addr):
    return '.'.join(map(str,addr))


# unpacking icmp diagnose problem within network

def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('! B B H', data[:4])
    return icmp_type,code,checksum,data[4:]


#unpack tcp

def tcp_segment(data):
    (src_port,dest_port,sequence,acknowledgement, offset_reserved_flags)=struct.unpack('! H H L L H',data[:14])
    offset=(offset_reserved_flags>>12)*4
    flag_urg=(offset_reserved_flags % 32)>>5
    flag_ack = (offset_reserved_flags % 16) >> 5
    flag_psh = (offset_reserved_flags % 8) >> 5
    flag_rst = (offset_reserved_flags % 4) >> 5
    flag_syn = (offset_reserved_flags % 2) >> 5
    flag_fin = offset_reserved_flags % 1

    return src_port,dest_port,sequence,acknowledgement, offset_reserved_flags, flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]
#udp unpacks
def udp_segment(data):
    src_port,dest_port,size=struct.unpack('!H H H', data[:6])
    return src_port,dest_port,size, data[8:]

def format_multi_line(prefix,string,size=80):
    size -= len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
