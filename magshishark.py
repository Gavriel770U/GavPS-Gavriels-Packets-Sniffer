from scapy.all import *
from colorama import Fore, Style

FUNCTIONS = {0 : "EXIT", 1 : "DNS", 2 : "Forecast", 3 : "HTTP", 4 : "E-mails"}

EMPTY_DOMAIN = ''
DNS_SNIFF_RESULT_ARROW = "===>"

HTTP_GET_PART_ONE_BINARY = "GET ".encode()
HTTP_GET_PART_TWO_BINARY = "HTTP/1.1".encode()
EMPTY_CHAR = ''

ENTER = '\n'
BACKSLASH_R = '\r'
EMPTY_CHAR = ''
GET_REQUEST_INDEX = 0

def dns_filter(packet) -> bool:
    """
    Function that checks if there is a DNS field in a packet. 
    :param packet: packet to check for DNS.
    :type packet: scapy.layers.l2.Ether
    :return: True if the packet contains DNS field, else False.
    :rtype: bool
    """
    
    return DNS in packet

def get_packet_dns_domain(packet) -> str:
    """
    Function that returns the domain of DNS field in a packet.
    :param packet: packet to get its domain. 
    :type packet: scapy.layers.l2.Ether
    :return: domain of DNS field in a packet.
    :rtype: str
    """

    if packet[DNS].qd != None:
        return packet[DNS].qd.qname.decode()
    return EMPTY_DOMAIN

def get_packet_src_ip(packet) -> str:
    """
    Function that returns the source ip of a packet.
    :param packet: packet to return its source ip.
    :type packet: scapy.layers.l2.Ether
    :return: the source ip of a packet
    :rtype: str
    """

    return packet[IP].src

def print_dns_packet_src_ip_and_domain(packet) -> None:
    """
    Function that prints the source ip and domain of DNS packet. 
    :param packet: packet to prints its source ip and domain.
    :type packet: scapy.layers.l2.Ether
    :return: None.
    :rtype: None
    """

    domain = get_packet_dns_domain(packet)
    src_ip = get_packet_src_ip(packet)
    print(Fore.MAGENTA+domain, DNS_SNIFF_RESULT_ARROW, src_ip+Style.RESET_ALL)

def http_get_filter(packet) -> bool:
    """
    Function that checks if a packet contains HTTP GET request.
    :param packet: packet to check if it has HTTP GET request field.
    :type packet: scapy.layers.l2.Ether
    :return: True if the packet contains HTTP GET request, else False.
    :rtype: bool
    """

    if Raw in packet:
        if packet[Raw].load != None:
            payload = packet[Raw].load
            return HTTP_GET_PART_ONE_BINARY in payload and HTTP_GET_PART_TWO_BINARY in payload 
    return False

def get_http_get_info(packet) -> str:
    """
    Function that returns HTTP GET request data without the GET / HTTP/1.1 string. 
    :param packet: packet to get its HTTP data.
    :type packet: scapy.layers.l2.Ether
    :return: the data of HTTP GET request field of the given packet.
    :rtype: str
    """
    return packet[Raw].load.decode()

def print_http_get_page(packet) -> None:
    """
    Function that prints HTTP GET request data page without the GET / HTTP/1.1 string.
    :param packet: packet to get its HTTP data page.
    :type packet: scapy.layers.l2.Ether
    :return: None.
    :rtype: None
    """

    components = get_http_get_info.split(ENTER)
    page = components[GET_REQUEST_INDEX] \
          .replace(HTTP_GET_PART_ONE_BINARY.decode(), EMPTY_CHAR) \
          .replace(HTTP_GET_PART_TWO_BINARY.decode(), EMPTY_CHAR) \
          .replace(BACKSLASH_R, EMPTY_CHAR)

    print(Fore.MAGENTA+page+Style.RESET_ALL)

def main() -> None:
    colorama.init()

    #packets = sniff(count=100, lfilter=dns_filter, prn=print_dns_packet_src_ip_and_domain)
    packets = sniff(count=5, lfilter=http_get_filter, prn=print_http_get_page)

if __name__ == "__main__":
    main()