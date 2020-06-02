import socket
import struct
import textwrap

def main():
    host = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind((host, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        #print(s.recvfrom(2048))
        raw_data, addr = s.recvfrom(2048)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """retrurns readable mac address (AA:BB:CC:DD:EE:FF)"""
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

if __name__ == "__main__":
    main()