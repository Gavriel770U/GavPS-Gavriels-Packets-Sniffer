from scapy.all import *
from colorama import Fore, Style
import re
import sys

EXIT_ACTION = "EXIT"
HTTP_ACTION = "HTTP"
DNS_ACTION = "DNS"
FORECAST_ACTION = "Forecast"
EMAILS_ACTION = "E-mails"

FUNCTIONS = {0 : EXIT_ACTION, 1 : DNS_ACTION, 2 : FORECAST_ACTION, 3 : HTTP_ACTION, 4 : EMAILS_ACTION}

EMPTY_DOMAIN = ''
DNS_SNIFF_RESULT_ARROW = "===>"

HTTP_GET_PART_ONE_BINARY = "GET ".encode()
HTTP_GET_PART_TWO_BINARY = "HTTP/1.1".encode()
EMPTY_CHAR = ''

ENTER = '\n'
BACKSLASH_R = '\r'
GET_REQUEST_INDEX = 0

WEATHER_SERVER_IP = '34.218.16.79'
WEATHER_SERVER_WELCOME_MSG = "Welcome to Magshimim's Forecast Server!\n"

SPACE_CHAR = ' '
EQUALS_CHAR = '='

INC = 1

HTTP_PORT = 80

EMPTY_LIST = []

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

    components = get_http_get_info(packet).split(ENTER)
    page = components[GET_REQUEST_INDEX] \
          .replace(HTTP_GET_PART_ONE_BINARY.decode(), EMPTY_CHAR) \
          .replace(HTTP_GET_PART_TWO_BINARY.decode(), EMPTY_CHAR) \
          .replace(BACKSLASH_R, EMPTY_CHAR)

    print(Fore.MAGENTA+page+Style.RESET_ALL)

def weather_client_filter(packet) -> bool:
    """
    Function that checks if a packet is a server response from Weather Client's server.
    :param packet: packet to check. 
    :type packet: scapy.layers.l2.Ether
    :return: true if positive, else false.
    :rtype: bool
    """

    return IP in packet and WEATHER_SERVER_IP == packet[IP].src

def get_weather_server_load(packet) -> str:
    """
    Function that returns the decoded load that is the weather server's response. 
    If there is no load the function will return empty string.
    :param packet: packet to return its load. 
    :type packet: scapy.layers.l2.Ether
    :return: decoded load of packet
    :rtype: str
    """

    if Raw in packet:
        return packet[Raw].load.decode()
    return EMPTY_CHAR
    
def print_weather_server_response(packet) -> None:
    """
    Function that prints the Weather Server's response if it is not empty or not an welcome message.
    :param packet: packet to print its response. 
    :type packet: scapy.layers.l2.Ether
    :return: None.
    :rtype: None
    """

    response = get_weather_server_load(packet)
    if EMPTY_CHAR != response and WEATHER_SERVER_WELCOME_MSG != response:
        print(Fore.MAGENTA+response+Style.RESET_ALL)

def is_email(text: str) -> bool:
    """
    Function that checks if a given texts is an e-mail.
    :param text: text to check. 
    :type text: str
    :return: True if the text is an e-mail, else False.
    :rtype: bool
    """

    # Regular expression pattern for email validation
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    
    # Check if the text matches the pattern
    if re.match(pattern, text):
        return True
    return False

def check_text_for_email(text: str) -> list:
    """
    Function that checks if there are e-mails in a given text. 
    :param text: text to search e-mails in it. 
    :type text: str
    :return: list of all e-mails found in the text.
    :rtype: list
    """

    components = text.split(SPACE_CHAR)
    emails = []

    for component in components:
        if EQUALS_CHAR in component:
            component = component[component.find(EQUALS_CHAR)+INC:]
        if is_email(component):
            emails.append(component)
    return emails

def http_filter(packet) -> bool:
    """
    Function that checks if a packet is a HTTP packet. 
    :param packet: packet to check.
    :type packet: scapy.layers.l2.Ether
    :return: True if positive, else False. 
    """
    
    if TCP in packet:
        return HTTP_PORT == packet[TCP].sport or HTTP_PORT == packet[TCP].dport
    elif UDP in packet:
        return HTTP_PORT == packet[UDP].sport or HTTP_PORT == packet[UDP].dport
    return False

def get_emails_from_http(packet) -> list:
    """
    Function that returns all e-mails from HTTP packet.
    :param packet: packet to get its e-mails.
    :type packet: scapy.layers.l2.Ether
    :return: list of all e-mails found.
    :rtype: list
    """

    if Raw in packet:
        if packet[Raw].load != None:
            try:
                emails = check_text_for_email(packet[Raw].load.decode())
                return emails
            except Exception:
                return EMPTY_LIST
    return EMPTY_LIST

def print_emails_from_http(packet) -> None:
    """
    Function that prints all e-mails in HTTP packet.
    :param packet: packet to print its e-mails.
    :type packet: scapy.layers.l2.Ether
    :return: None.
    :rtype: None
    """

    emails = get_emails_from_http(packet)
    for email in emails:
        print(Fore.MAGENTA+email+Style.RESET_ALL)

def do_action(action: str) -> None:
    """
    Function that does a given action. 
    :param action: action to do. 
    :type action: str
    :return: None.
    :rtype: None
    """

    if EXIT_ACTION == action:
        sys.exit()
    elif DNS_ACTION == action:
        try:
            packets = sniff(lfilter=dns_filter, prn=print_dns_packet_src_ip_and_domain)
        except KeyboardInterrupt:
            print(EMPTY_CHAR)
            return 
    elif FORECAST_ACTION == action:
        try:
            packets = sniff(lfilter=weather_client_filter, prn=print_weather_server_response)
        except KeyboardInterrupt:
            print(EMPTY_CHAR)
            return 
    elif HTTP_ACTION == action:
        try:
            packets = sniff(lfilter=http_get_filter, prn=print_http_get_page)
        except KeyboardInterrupt:
            print(EMPTY_CHAR)
            return 
    elif EMAILS_ACTION == action:
        try:
            packets = sniff(lfilter=http_filter, prn=print_emails_from_http)
        except KeyboardInterrupt:
            print(EMPTY_CHAR)
            return 

def main() -> None:
    try:
        option = int(input("""Please select sniffing state:
    1. DNS 
    2. Forecast
    3. HTTP
    4. E-mails
    Or select 0 to Exit: """))
        
    except Exception:
        print(Fore.RED+"Inavlid option!"+Style.RESET_ALL)
    except KeyboardInterrupt:
        print(Fore.RED+"Inavlid option!"+Style.RESET_ALL)
    
    try:
        action = FUNCTIONS[option]
        do_action(action)
    except Exception:
        print(Fore.RED+"Inavlid option!"+Style.RESET_ALL)

if __name__ == "__main__":
    colorama.init()

    running = True
    while running:
        main()
