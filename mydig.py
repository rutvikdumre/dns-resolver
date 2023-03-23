from turtle import rt
import dns
import dns.name
import dns.message
import dns.query
import dns.flags
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.NS
import time
import sys
import time
import datetime

# list of root servers to be checked 
root_server_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

og_name=''

def iterative_resolver(name, rtype, server):
    
    query = dns.message.make_query(name, rtype)
    response=dns.query.udp(query, str(server))
    cname=False
    
    # get response and check for answer, additional and authority section of the response 

    if response.answer:
        
        if response.answer[0][0].rdtype==5: 
            # check for canonical name 
            link=response.answer[0][0].to_text()                # get CNAME link 
            print('{}   IN  CNAME {}'.format(og_name, link))    # print CNAME link
            cname= True
                                                                # if found then hit the root with the cname link and start over
            return iterate(link, rtype)     
        else:
                                                                # if response has IP in the answer then return answer
            return response.answer


    elif response.additional:
                                                                # if response has information about additional servers (ipv4 addresses) then use them
        for i in response.additional:
                                                                # get all ipv4 addresses 
            if '::' not in str(i[0]):
                add_servers= str(i[0])
                                                                # hit the additional servers 
                return iterative_resolver(name, rtype, add_servers)

    elif response.authority:
                                                                # Check if response has authority section 
                                                                # get links of from the authority section
        if response.authority[0].rdtype==dns.rdatatype.SOA:
            # check for SOA 
            if 'www.' in og_name  or (cname and rtype in ['MX', 'NS']):
                return response.authority

                                                                # if soa; then query the orignal domain name and return answer
            querysoa = dns.message.make_query(og_name, rtype)
            responsesoa =dns.query.udp(querysoa, str(server))
            
            if responsesoa.answer:
                return responsesoa.answer
            
        else:
                                                                # get links from the authority section and hit root with it 
            for j in str(response.authority[0]).split('\n'):
                j=j.split()
                k=''+str(j[-1])
                a=iterate(k, rtype)                 
                if a:
                    return a 
    else:
        return 0
        

                                                                #Iterate over the root servers 
def iterate(domain, rtype):                            

    for server in root_server_list:
        ans= iterative_resolver(domain, rtype, server)
        if ans:
            return ans
        return None

def get_rtime(website):
    # for part C
    hostname=website
    rtype = 'A'
    global og_name
    og_name=website
    start_time = time.time() 
    ans=iterate(hostname, rtype) 
    time_taken = time.time() - start_time

    return time_taken

if __name__ == "__main__":
    hostname = sys.argv[1]                                      # command line input for hostname 
    rtype = sys.argv[2]                                         # command line input for type
    
    og_name=hostname
    start_time = time.time()                                    # Initialize time 
    print('QUESTION SECTION:')
    print('{} IN {}'.format(og_name, rtype))
    print()
    print('ANSWER SECTION:')
    ans=iterate(hostname, rtype)                                # Calling the iterative resolver 
    
    for i in ans[0]:
        print('{}   IN  {}'. format(og_name, i))                # print the resolved information 

    time_taken = time.time() - start_time
    print()
    print('Query time: {:.2f} msec'.format(time_taken*1000))    # print the time taken for resolution 
    print('WHEN: {}'.format(datetime.datetime.now()))
    print( "MSG SIZE rcvd: " + str(sys.getsizeof(ans)))


