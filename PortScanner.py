import nmap

scanner = nmap.PortScanner()


print("Welcome to NMAP PORT SCANNER")

print("Enter the ip address you want to run scan on")
ip_addr = input()

resp = input("\nKindly select the scan type you want to run on the ip address " + ip_addr +
          "\n1) SYN & ACK Scan"
          "\n2) UDP Scan"
          "\n3) Comprehensive Scan \n")

if resp == '1':
    print("NMAP Version: ",scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ",scanner[ip_addr]['tcp'].keys())



   
elif resp == '2':
    print(scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print(scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

else:
    "Please select a valid option"


