import dpkt, datetime, socket, time, struct, sys, re #need to do a pip install dpkt before running code otherwise it wont run
from dpkt.compat import compat_ord # imported to do the reorder for mac addresses


print('Created by \nKyle Angell Walker N0832083\nLewis Niblett N0814049 \nJosh Evans N0803705 \n') #so they know who we are lol



file = "CyberSecurity.pcap"

def macAdd(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)
#a quick function made to turn the bytes code into a mac address for easy reading


def headerLen():
    head=open(file,"rb") # opens the pcap as head
    header= head.read(24)#reads the total bytes in the header
    headerlen=str(int.from_bytes(header, byteorder='little')) # turns it into a string and reorders by little endian
    hl=len(headerlen)#tells me the length of the sting
    print('1a) Global header length :', hl)
    head.close()#closes the file after reuse- have to keep doing this otherwise the file carries on reading from this point and gets confused and throws the read order out later

def magicNo():
   
    pcap= open(file,"rb")
    magic= pcap.read(4)
    magicNo=macAdd(magic)
    print("1b) Magic Number :", magicNo)  #prints magic number 
    if magicNo ==("d4:c3:b2:a1"):## this is the magicnumber for little endian. as per lab 10 paperwork
        global end # declares end as global to be used in other functions
        end='little' # makes end varliable little where ever end is used with int.from_bytes it takes it from this
        print("Little endian found")           
    else:
        print("big endian found")
        
       
    major=pcap.read(2) #pretty much taken from the lab 10, used int from bytes to reorder little 1st as magic number states 
    m=int.from_bytes(major,byteorder=end)
    print('1c) Major No :', m)
    minor=pcap.read(2)
    minorNo=int.from_bytes(minor,byteorder=end) #gets the end from the global variable above
    print('1c) Minor No :',minorNo)
    
    skipToNextZone=pcap.read(8)#skips timezone for next section as we dont need it yet
    
    snaplen=pcap.read(4)
    snap=int.from_bytes(snaplen,byteorder=end)
    if snap != 65535:
        print("1d) Max packets not captured, cap amount Snaplen :", snap) #as per lab10 if snaplen is 65535 then all packets captured
    else:
        print("1d) Snaplen :", snap, "**Max length of packets captured")
    
    link = pcap.read(4)
    linktype=int.from_bytes(link,byteorder=end)
    if linktype == 1:        
        print("1e) linktype :", linktype, "** ethernet connection confirmed") #if link type returns 1 (which it should) then it confirmed its an ethernet
    else:
        print("1e) linktype not 1") # else in place just incase for what ever reason
    pcap.close()
    
def Timestamps():
    f=open(file,'rb')
    pcap=dpkt.pcap.Reader(f)
    for timestamp, buf in pcap: # taken from dpkt example as below     
        print("2a) Timestamp of capture", timestamp,"seconds since Unix time") # not sure if this is the format they need the timestamp in, need to clarify with tari
        utc=str(datetime.datetime.utcfromtimestamp(timestamp)) #utc and gmt are the same thing??
        print('2b) Timestamp GMT :', utc)
        break    
    
    
def dchpLen():
    f=open(file,'rb')
    pcap=dpkt.pcap.Reader(f)
    for timestamp, buf in pcap: # taken from dpkt example as below
        eth=dpkt.ethernet.Ethernet(buf)
        ip=eth.data
        udp=ip.data
        dhcp=dpkt.dhcp.DHCP(udp.data)
        d=str(int.from_bytes(dhcp, byteorder=end))
        print('2c) DCHP Length :', len(d))
        break

def mac(): #gets the mac address and ip addresses from dkpt for source and destination
    f=open(file,'rb')
    pcap=dpkt.pcap.Reader(f)
    for ts, buf in pcap: ##code taken from the dpkt documentation.
        eth=dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src=socket.inet_ntoa(ip.src)
        dst= socket.inet_ntoa(ip.dst)
        macs = macAdd(eth.src)
        macd = macAdd(eth.dst)
        print ('2d) source mac :', macs, '\ndest mac :', macd)
        print ('2e) source IP :', src, '\ndest IP :', dst)
        break

def hostName():
    with open(file,'rb') as dhcp:
        host = dhcp.read(372)#skip 298 bytes to get host name
        hostname = dhcp.read(9)# read the hostname from dchp
        hn=(hostname.decode()).split(" ")[0] # decodes from utf and then splits at the space so it doesnt print the b
        print('2f) Host PC Name :', str(hn)) # as bytes not a string

        
def sec3():
    
   #uses re (regular expression) import to check and search for a .top website
    
        f=open(file,'rb')#starts with statement which is read pcap save as file
        for site in f:#starts the for loop to search the file
            if re.search(b"(.top)", site):#searched for .top at the end of a line 
                if re.search(b"(Origin)", site):#searches for origin line which is shown on wireshark to start
                    found= (site.decode()).split(" ")[1]
                    #site.decode decodes it from utf8 and then splits it so it doesnt print b''
                    #site.decode also puts it in plane english otherwise it would be stuck in 'rb' which is bytes
                    #the [1] gets rid of the 1st arg so as to just print the site rather than the full thing
                    print('Suspected website found :', found)
    

def searchUsed():
    #everything in this is a repeat of above searching for different criteria every time
    
    #search engine used for section 4
        f=open(file,'rb')#starts with statement which is read pcap save as file
        for site in f:#starts the for loop to search the file
            if re.search(b'(.com)', site):#searched for .com at the end of a line
                if re.search(b'(Origin)', site):#searches for origin line, shown on wireshark to be bing
                    engine = (site.decode()).split(' ')[1]
                    print('Search engine used :', engine)
                    #break#stops it from printing anything else
                
def keyWord():    
    #keyword filter for section 4  
        f=open(file,'rb')
        for site in f:
            if re.search(b'.com/s', site):#same as the first search just this preference will gather any line which has .com/s
                #s stands for search in this instance because thats how saved searches look like and thats the data we need
                if re.search(b'(Referer)', site):
                    key = (site.decode()).split(' ')[1]
                    start = key.split('&qs')[0] # splits at &qs which is at the end of the search and prints the 1st half not the 2nd
                    final = start.split('=')[1] #prints everything after the = in the site leaving just the keywords
                    keyword = final.replace('+', ' ')#replaces the + between words with spaces to leave readable keywords
                    print('Keywords the user has used :', keyword)
                    break
def searchEng():
    #search engine recommendation for section 4
        f=open(file,'rb')
        for site in f:
            if re.search(b'(.html)', site):#same as above except looking for a line ending in .html
                if re.search(b'(Referer)', site):#same as above except looking for the line that starts with Referer
                    search = (site.decode()).split(' ')[1]
                    print('\nSearch engine recommended and used :', search)
                    break   

def secTool():
    print('\nThis tool will scan pcap file to check for any sites found without a www.\nThese websites are possibly malicious therefore will be flagged up\n')
    time.sleep(2)
    t=1 # counter for sites
   
    f=open(file,'rb')
    for each in f:
        if re.findall(b'(.com)', each):#same as before but its looking for a line ending in .com
            if re.findall(b'(Host)', each):#same as prior but its looking for the line that starts with Referer
                suspect = (each.decode()).split(' ')[1]#same as before just repeated code
                if 'www.'not in suspect: #stops any website starting with www. does not print 
                    print('Possible Site',t,' :', suspect)
                    t=t+1 # add one to the counter for next print
                    time.sleep(0.5) # sleep timer so it doesnt spam the shit 
                       



print("\n\nSection 1\n") # following functions operate section 1
headerLen()
magicNo()
print("\n\nSection 2\n") # following functions operate section 2
Timestamps()
dchpLen()
mac()
hostName()
print("\n\nSection 3\n") # following functions operate section 3
sec3()
print("\n\nSection 4\n") # following functions oeprate section 4
searchUsed()
keyWord()
searchEng()
print("\n\nSection 5\n") 
secTool()




#http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm
#https://stackoverflow.com/questions/55243226/using-python-to-search-through-a-pcap-file-and-return-key-information-about-the
#https://docs.python.org/3/library/stdtypes.html#bytes.hex
#https://morioh.com/p/f2ddc1158f5d
#https://docs.python.org/3.2/library/stdtypes.html - where we got the intfrombytes bit from
#https://dpkt.readthedocs.io/en/latest/ - where the mac and ip address bit is from (in the examples bit)
#https://www.elvidence.com.au/understanding-time-stamps-in-packet-capture-data-pcap-files/
