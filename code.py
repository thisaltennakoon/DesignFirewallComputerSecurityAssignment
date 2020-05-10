import configparser
import datetime

def convert_binary(data):#convert character to a binary string
    return ''.join(format(ord(i), 'b') for i in data)

def is_binary_string(data):#check given input is a binary string
    for i in data:
        if i=='0' or i=='1':
            continue
        else:
            return False
    return True

def tcp(data,source_port,destination_port):#Create TCP packet
    sequence_number=4*8*'0'
    acknowledgement_number=4*8*'0'
    data_offset=4*'0'
    reserved=3*'0'
    control_flags=9*'0'
    window_size=2*8*'0'
    checksum=2*8*'0'
    urgent_pointer=2*8*'0'
    optional_data=0*8*'0'
    source_port_binary=bin(source_port)[2:]
    if len(source_port_binary)<=16:
        source_port_binary=((16-len(source_port_binary))*'0')+(source_port_binary)
    else:
        return False
    destination_port_binary=bin(destination_port)[2:]
    if len(destination_port_binary)<=16:
        destination_port_binary=((16-len(destination_port_binary))*'0')+(destination_port_binary)
    else:
        return False
    if is_binary_string(data):
        return source_port_binary + destination_port_binary + sequence_number + \
               acknowledgement_number + data_offset + reserved + control_flags + \
               window_size + checksum + urgent_pointer + optional_data + data
    else:
        return False

def udp(data,source_port,destination_port):#create UDP packet
    length=2*8*'0'
    checksum=2*8*'0'
    source_port_binary=bin(source_port)[2:]
    if len(source_port_binary)<=16:
        source_port_binary=((16-len(source_port_binary))*'0')+(source_port_binary)
    else:
        return False
    destination_port_binary=bin(destination_port)[2:]
    if len(destination_port_binary)<=16:
        destination_port_binary=((16-len(destination_port_binary))*'0')+(destination_port_binary)
    else:
        return False
    if is_binary_string(data):
        return source_port_binary + destination_port_binary + length + checksum + data
    else:
        return False


def ip(data,source_address,destination_address):#Create a IP datagram
    version='0100'
    HLEN='0101' #Assumption: no options included in this ip header.therefore minimum is 5(maximum is 15)
    type_of_service=8*'0'
    total_length=16*'0'
    trusted_host_id=16*'0'
    flags=3*'0'
    fragment_offset=13*'0'
    time_to_live=8*'0'
    protocol=8*'0'
    header_checksum=16*'0'
    options_and_padding=0*'0'
    source_address_binary=''
    for i in source_address.split('.'):
        one_segment=bin(int(i))[2:]
        if len(one_segment) <= 8:
            source_address_binary += ((8 - len(one_segment)) * '0') + (one_segment)
        else:
            return False
    destination_address_binary=''
    for i in destination_address.split('.'):
        one_segment=bin(int(i))[2:]
        if len(one_segment) <= 8:
            destination_address_binary += ((8 - len(one_segment)) * '0') + (one_segment)
        else:
            return False
    if is_binary_string(data):
        return version + HLEN + type_of_service + total_length + trusted_host_id + flags + fragment_offset + time_to_live+ protocol+ header_checksum  + source_address_binary + destination_address_binary + options_and_padding + data
    else:
        return False


#(Start)Read IP and TCP/UDP headers to a data structure####################################################################################################################################################################################################


def read_ipv4_packet(bit_string):#Read ipv4 packet and extract source_address,destination_address.Also,it returns Transport layer part of a given binary string(TCP or UDP packet).
    source_address = str(int(bit_string[96:104],2))+'.'+ str(int(bit_string[104:112],2))+'.'+ str(int(bit_string[112:120],2))+'.'+ str(int(bit_string[120:128],2))
    destination_address = str(int(bit_string[128:136], 2)) + '.' + str(int(bit_string[136:144], 2)) + '.' + str(int(bit_string[144:152], 2)) + '.' + str(int(bit_string[152:160], 2))
    HLEN=int(bit_string[4:8],2)
    transport_layer_string=bit_string[(HLEN*32):]
    return source_address,destination_address,transport_layer_string

def read_transport_layer_packet(bit_string):
    source_port=int(bit_string[0:16],2)
    destination_port=int(bit_string[16:32],2)
    return source_port,destination_port

def read_packet_to_dictionary(bit_string):
    (source_address,destination_address,transport_layer_string) = read_ipv4_packet(bit_string)
    (source_port,destination_port) = read_transport_layer_packet(transport_layer_string)
    return {'source_address':source_address,'destination_address':destination_address,'source_port':source_port,'destination_port':destination_port}


#(End)Read IP and TCP/UDP headers to a data structure####################################################################################################################################################################################################

def firewall(dictionary):
    #(Start)Read firewall filtering rules from a configuration file#####################################
    rules=[]
    config = configparser.ConfigParser()
    config.read('firewall_config.ini')
    i=1
    while True:
        try:
            rules += [[config['SourceIP'][str(i)],config['DestinationIP'][str(i)],config['SourcePort'][str(i)],config['DestinationPort'][str(i)],config['Action'][str(i)]]]
            i+=1
        except:
            break
    source_address=dictionary['source_address'] #0
    destination_address=dictionary['destination_address'] #1
    source_port=str(dictionary['source_port']) #2
    destination_port=str(dictionary['destination_port']) #3
    # (End)Read firewall filtering rules from a configuration file#####################################
    #(Start)Accept or reject IP datagrams from one network interface to be forwarded to the other interface#########################
    for rule in rules:
        if source_address==rule[0]:
            if rule[1]=='any' or rule[1]==destination_address:
                if rule[2]=='any' or rule[2]==source_port:
                    if rule[3] == 'any' or rule[3] == destination_port:
                        if rule[4] == 'allow':
                            return True
                        elif rule[4] == 'deny':
                            return False
                    else:
                        continue
                else:
                    continue
            else:
                continue
        else:
            continue

    for rule in rules:
        if destination_address==rule[1]:
            if rule[0]=='any' or rule[0]==source_address:
                if rule[2]=='any' or rule[2]==source_port:
                    if rule[3] == 'any' or rule[3] == destination_port:
                        if rule[4] == 'allow':
                            return True
                        elif rule[4] == 'deny':
                            return False
                    else:
                        continue
                else:
                    continue
            else:
                continue
        else:
            continue

    for rule in rules:
        if source_port==rule[2]:
            if rule[0]=='any' or rule[0]==source_address:
                if rule[1]=='any' or rule[1]==destination_address:
                    if rule[3] == 'any' or rule[3] == destination_port:
                        if rule[4] == 'allow':
                            return True
                        elif rule[4] == 'deny':
                            return False
                    else:
                        continue
                else:
                    continue
            else:
                continue
        else:
            continue

    for rule in rules:
        if destination_port==rule[3]:
            if rule[0]=='any' or rule[0]==source_address:
                if rule[1]=='any' or rule[1]==destination_address:
                    if rule[2] == 'any' or rule[2] == source_port:
                        if rule[4] == 'allow':
                            return True
                        elif rule[4] == 'deny':
                            return False
                    else:
                        continue
                else:
                    continue
            else:
                continue
        else:
            continue
    # (End)Accept or reject IP datagrams from one network interface to be forwarded to the other interface#########################

def network_interface_1():
    data=[]
    config = configparser.ConfigParser()
    config.read('network_interface_1.ini')#reading data of network_interface_1 to be sent to the other interface from configuration file
    i=1
    while True:
        try:
            data += [[config['data'][str(i)],int(config['source_port'][str(i)]),int(config['destination_port'][str(i)]),config['source_ip'][str(i)],config['destination_ip'][str(i)],config['protocol'][str(i)]]]
            i+=1
        except:
            break
    for i in data:
        data=i[0]
        source_port=i[1]
        destination_port=i[2]
        source_ip=i[3]
        destination_ip=i[4]
        protocol=i[5]
        if protocol=='tcp':
            firewall_interface('network_interface_1', ip(tcp(convert_binary(data),source_port,destination_port),source_ip,destination_ip))
        elif protocol=='udp':
            firewall_interface('network_interface_1',ip(udp(convert_binary(data), source_port, destination_port), source_ip, destination_ip))

def network_interface_2():
    data=[]
    config = configparser.ConfigParser()
    config.read('network_interface_2.ini')#reading data of network_interface_2 to be sent to the other interface from configuration file
    i=1
    while True:
        try:
            data += [[config['data'][str(i)],int(config['source_port'][str(i)]),int(config['destination_port'][str(i)]),config['source_ip'][str(i)],config['destination_ip'][str(i)],config['protocol'][str(i)]]]
            i+=1
        except:
            break
    for i in data:
        data=i[0]
        source_port=i[1]
        destination_port=i[2]
        source_ip=i[3]
        destination_ip=i[4]
        protocol=i[5]
        if protocol=='tcp':
            firewall_interface('network_interface_2', ip(tcp(convert_binary(data),source_port,destination_port),source_ip,destination_ip))
        elif protocol=='udp':
            firewall_interface('network_interface_2',ip(udp(convert_binary(data), source_port, destination_port), source_ip, destination_ip))

def firewall_interface(network_interface,input_data):
    firewall_response = firewall(read_packet_to_dictionary(input_data))
    if firewall_response==True:
        print('Packet has been accepted of '+network_interface+' at '+ str(datetime.datetime.now()))
    else:
        print('Packet has been rejected of ' + network_interface + ' at ' + str(datetime.datetime.now()))

network_interface_1()
network_interface_2()