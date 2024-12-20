Traceroute Tool
========

This tool implements a simplified version of Traceroute using ICMP messages. It builds upon a raw socket ICMP ping implementation to trace the route from the local machine to a target host on the internet. The program sends ICMP Echo Requests with increasing TTL (Time-To-Live) values, and the routers along the route respond with ICMP Time Exceeded messages when the TTL expires. The destination host sends an ICMP Echo Reply message upon receipt of the Echo Request.

## Objectives

  - Enhance Raw Socket ICMP Ping: Extend the ping implementation to track the route to a target host.
  - Validate ICMP Reply: Ensure the received ICMP Echo Reply matches the sent data (e.g., sequence number, packet identifier, raw data).
  - Implement Traceroute: Use increasing TTL values to trace the route to the destination and print detailed results.
  - Handle Error Codes: Parse ICMP error response types and codes, such as Destination Unreachable (Type 3) and Time Exceeded (Type 11).
  - Output Summary: Display minimum, maximum, and average RTT values and calculate packet loss rate.

## Requirements
  - Python 3: This project requires Python 3 to run.
  - Root/Administrator Privileges: On Linux-based systems, you may need to run the script with sudo to use raw sockets:
```
sudo python3 IcmpHelperLibrary.py
```
  - ICMP Echo Requests and Responses: Make sure your firewall or antivirus software does not block ICMP traffic.
