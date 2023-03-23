import dns
import dns.name
import dns.message
import dns.query
import dns.flags
import time
import datetime
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import sys

root_server_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
result=[]
# first previous key is initialized to None 
parent_DS = None


def pass1(res_parent, parent_name):
    # Helper function for validate
    try:
        # validate using dnspython's inbuilt validate function
        dns.dnssec.validate(res_parent.answer[0], res_parent.answer[1], {parent_name:res_parent.answer[0]})
        print ("DNSSEC Pass 1 Validated!")
    except dns.dnssec.ValidationFailure:
        print ("DNSSEC validation failed")
        exit()

def validate(name, nserver):
    print('---------------------------')
    print('Validating zone: {}'.format(name))

    # The previous DNS key which is a global variable 
    global parent_DS
    # get parent 
    s = "."
    if (name.find('.')!=-1):
        parent = name[name.index(s) + len(s):]
    else:
        parent = "."

    
    # query for parents 
    request = dns.message.make_query(parent, dns.rdatatype.DNSKEY, want_dnssec=True)
    res_parent = dns.query.tcp(request, nserver, timeout = 1)
    # query for child
    request = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
    res_child = dns.query.tcp(request, nserver, timeout = 1)
       

    parent_name = dns.name.from_text(parent)
    DNSkey = res_parent.answer[0]
    
    pass1(res_parent, parent_name)

    # get DS and rrsig for the child 
    if res_child.answer:
        DS = res_child.answer[0]
        rrsig_DS = res_child.answer[1]
    else:
        DS = res_child.authority[1]
        rrsig_DS = res_child.authority[2]

    # if DS is an object of NSEC or NSEC3 then the domain does not support DNSSec
    if (isinstance(DS[0], dns.rdtypes.ANY.NSEC.NSEC) or isinstance(DS[0], dns.rdtypes.ANY.NSEC3.NSEC3)):
        print ("DNSSEC not supported for the domain!")
        exit()

    else:
        # Make a query for the child and then validate the RRSIG and DS
        try:
            dns.dnssec.validate(DS, rrsig_DS, {parent_name:res_parent.answer[0]})
            print ("DNSSEC Pass 2 Validated!")
        except dns.dnssec.ValidationFailure:
            print ("DNSSEC: Validation failed")
            exit()

        # check the DS with the previous DS using SHA256
        for entry in DNSkey:
            str_tokens = str(entry).split(" ")
            if(str_tokens[0] == '257'):
                newds = dns.dnssec.make_ds(parent_name, entry, 'SHA256')
                if parent_DS != None:
                    if parent_DS[0] == newds:
                        print ("DNSSEC Pass 3 Validated!")
                        parent_DS = DS
                        break
                    else:
                        print ("Cannot validate : Validation failed!")
                        exit()
                else:
                    print ("Skipped validation: Not validating root!")
                    parent_DS = DS
                    break


def append_result(response, start_time):
    # append the results by the resolver into a list
    global result
    if response.answer:
        for i in response.answer:
            result+=[i]
    if response.additional:
        for i in response.additional:
            result+= [i]
    if response.authority:
        for i in response.authority:
            result+= [i]


def query_with_validator(name, dns_server, type, validation):
    request = dns.message.make_query(name, dns.rdatatype.A)
    
    response = dns.query.udp(request, dns_server)
    if validation:
        validate(name, dns_server)
    
    return response

def iterative_resolver(name, type, start_time, print_res):
   # divide name in zones
    if name.endswith('.'):
        name = name[:-1]
    zones = name.split(".")
    zones.reverse()
    new_zone = zones[0]
    i = 1


    for new_server in root_server_list:
        # iterate through all the zones -> validate DNSSEC -> resolve for that zone
        while(i < len(zones)+1):
            
            # resolve the zone if validated
            query_response = query_with_validator(new_zone, new_server, type, True)

            if (query_response != None):

                if query_response.answer:
                    for rdata in query_response.answer:
                        if(rdata.rdtype == 1 or rdata.rdtype == 2 or rdata.rdtype == 15):
                            if(print_res == 1):
                                append_result(query_response, start_time)
                            return query_response
                        if(rdata.rdtype == 5):                                                          # check for CNAME
                            iterative_resolver(str(rdata[0].target), type, start_time, 1)
                            return query_response

                # check for additional servers
                if query_response.additional:
                    for rdata in query_response.additional:
                        if(rdata.rdtype == 1):
                            new_server = rdata[0].address
                            if(i < len(zones)):
                                
                                new_zone = zones[i] + "." + new_zone
                                i += 1
                                check_response = query_with_validator(new_zone, new_server, type, False)
                                if(check_response != None):
                                    break
                                else:
                                    continue
                            
                            else:
                                query_response = query_with_validator(new_zone, new_server, type, False)
                                if(query_response != None):
                                    if query_response.answer:
                                        if(query_response.flags & dns.flags.AA ==  dns.flags.AA):
                                            for rdata in query_response.answer:  
                                                if(rdata.rdtype == 1):
                                                    if(print_res == 1):
                                                        append_result(query_response, start_time)
                                                    return query_response
                                    if query_response.authority:
                                        for rdata in query_response.authority:
                                            if(rdata.rdtype == 6):
                                                if(print_res == 1):
                                                    append_result(query_response, start_time)
                                                return query_response
                                else:
                                    continue
                else:

                    if query_response.authority:
                        for rdata in query_response.authority:
                                if(rdata.rdtype == 6 or rdata.rdtype == 2):
                                    if(i < len(zones)):
                                        
                                        new_zone = zones[i] + "." + new_zone
                                        i += 1
                                    
                                    query_response = query_with_validator(new_zone, new_server, type, False)
                                    if(query_response != None):
                                        
                                        for itr1 in query_response.authority:
                                            if(itr1.rdtype == 2):
                                                new_response = iterative_resolver(str(itr1[0].target), type, start_time, 0)
                                                if new_response:
                                                    if new_response.answer:
                                                        for itr2 in new_response.answer:
                                                            if(itr2.rdtype == 1):
                                                                new_server = itr2[0].address
                                                                check_response = query_with_validator(new_zone, new_server, type, False)
                                                                if(check_response != None):
                                                                    break
                                                                else:
                                                                    continue
                                                        query_response = query_with_validator(new_zone, new_server, type, False)
                                                        if(print_res == 1):
                                                            append_result(query_response, start_time)
                                                        return
                                                    else:
                                                        continue
                                                else:
                                                    continue
                                    else:
                                        continue
            else:
                break
   




# driver code 

start_time = time.time()
hostname = sys.argv[1]                              # only the domain name is taken as an input     
  
iterative_resolver(hostname, 'A', start_time, 1)    # the code checks suupport for DNSSEC in type 'A' only 
print()
print('DNSSEC is Supported by the domain!')
print()
print('-----------DNS resolution------------')
print('QUESTION SECTION:')
print('{} IN {}'.format(hostname, 'A'))
print()
print('ANSWER SECTION:')                            # if domain supports DNSSEC then resolution is printed
for i in result:
    print(i)