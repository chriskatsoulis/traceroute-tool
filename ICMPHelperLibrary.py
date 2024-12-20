# Citation for the following program: ICMPHelperLibrary.py
# Date: 12/1/2024
# Adapted from: Skeleton code provided on assignment page, Ed Discussion posts, articles,
#               and ChatGPT's methods for formatting string literal alignment and ignoring
#               utf-8 decoding errors (lines 319, 334, 349, 586-590).
# Source URLs: https://canvas.oregonstate.edu/courses/1975660/assignments/9808067?module_item_id=24788994
#              https://edstem.org/us/courses/67690/discussion/5763864
#              https://edstem.org/us/courses/67690/discussion/5768883
#              https://edstem.org/us/courses/67690/discussion/5791711
#              https://phoenixnap.com/kb/how-to-run-traceroute
#              https://pimylifeup.com/mac-os-ping-command/

# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import math


# #################################################################################################################### #
# Public Variables                                                                                                     #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
rtt_list = []
packets_sent = 0
packets_dropped = 0
ping_complete = False

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                      # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Obtain sequence number, packet identifier, and raw data from ICMP reply packet.
            reply_sequence_number = icmpReplyPacket.getIcmpSequenceNumber()
            reply_packet_identifier = icmpReplyPacket.getIcmpIdentifier()
            reply_raw_data = icmpReplyPacket.getIcmpData()

            # Compare ICMP reply packet values to the original ICMP packet, set valid response accordingly,
            # and print debug messages if necessary.
            if self.__packetSequenceNumber != reply_sequence_number or self.__packetIdentifier != reply_packet_identifier or self.__dataRaw != reply_raw_data:
                print("ECHO REPLY IS INVALID")
            if self.__packetSequenceNumber != reply_sequence_number:
                icmpReplyPacket.setIsValidResponse(False)
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(f"Expected Sequence Number: {self.__packetSequenceNumber}, Actual Sequence Number: {reply_sequence_number}")
            if self.__packetIdentifier != reply_packet_identifier:
                icmpReplyPacket.setIsValidResponse(False)
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(f"Expected Packet Identifier: {self.__packetIdentifier}, Actual Packet Identifier: {reply_packet_identifier}")
            if self.__dataRaw != reply_raw_data:
                icmpReplyPacket.setIsValidResponse(False)
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(f"Expected Raw Data: {self.__dataRaw}, Actual Raw Data: {reply_raw_data}")
            else:
                icmpReplyPacket.setIsValidResponse(True)
                icmpReplyPacket.setIcmpIdentifier_isValid(True)


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def printPingTarget(self):
            # Signal the ping target by printing the target's name and IP address.
            print("-----------------------------------------------------------------")
            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            print("-----------------------------------------------------------------")

        def printTracerouteTarget(self):
            # Signal the traceroute target by printing the target's name and IP address.
            print("-------------------------------------------------------------------------------------------------------------------------")
            print("Traceroute to (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            print("-------------------------------------------------------------------------------------------------------------------------")

        def sendPingEchoRequest(self, ttl, packet_num):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            global rtt_list
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:  # Time Exceeded
                        print("  TTL={:<4} RTT={:<6.0f} ms Type={:<2} Code={:<2} Address={:<15}".format(
                            ttl,
                            (timeReceived - pingStartTime) * 1000,
                            icmpType,
                            icmpCode,
                            addr[0]
                        ))
                        # Save RTT to rtt_list under "Public Variables".
                        rtt_list.append((timeReceived - pingStartTime) * 1000)

                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printPingResultToConsole(packet_num)

                    elif icmpType == 3:  # Destination Unreachable
                        print("  TTL={:<4} RTT={:<6.0f} ms Type={:<2} Code={:<2} Address={:<15}".format(
                            ttl,
                            (timeReceived - pingStartTime) * 1000,
                            icmpType,
                            icmpCode,
                            addr[0]
                        ))
                        # Save RTT to rtt_list under "Public Variables".
                        rtt_list.append((timeReceived - pingStartTime) * 1000)

                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printPingResultToConsole(packet_num)

                    elif icmpType == 0:  # Echo Reply
                        print("  TTL={:<4} RTT={:<6.0f} ms Type={:<2} Code={:<2} Address={:<15}".format(
                            ttl,
                            (timeReceived - pingStartTime) * 1000,
                            icmpType,
                            icmpCode,
                            addr[0]
                        ))
                        # Save RTT to rtt_list under "Public Variables".
                        rtt_list.append((timeReceived - pingStartTime) * 1000)

                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printPingResultToConsole(packet_num)

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def sendTraceEchoRequest(self, ttl, packet_num):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    # Save RTT to rtt_list under "Public Variables".
                    global rtt_list
                    rtt_list.append((timeReceived - pingStartTime) * 1000)

                    if icmpType == 11 and packet_num == 3:  # Time Exceeded
                        min_rtt = min(rtt_list)
                        max_rtt = max(rtt_list)
                        avg_rtt = sum(rtt_list) / len(rtt_list)
                        print("  TTL=%d        MinRTT=%.0f ms        MaxRTT=%.0f ms        AvgRTT=%.0f ms        Type=%d        Code=%d        %s" %
                              (
                                  ttl,
                                  int(min_rtt),
                                  math.ceil(max_rtt),
                                  int(avg_rtt),
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )
                        # Reset rtt_list for next ping.
                        rtt_list = []

                    elif icmpType == 3 and packet_num == 3:  # Destination Unreachable
                        min_rtt = min(rtt_list)
                        max_rtt = max(rtt_list)
                        avg_rtt = sum(rtt_list) / len(rtt_list)
                        print(
                            "  TTL=%d    MinRTT=%.0f ms    MaxRTT=%.0f ms    AvgRTT=%.0f ms    Type=%d    Code=%d    %s" %
                            (
                                ttl,
                                int(min_rtt),
                                math.ceil(max_rtt),
                                int(avg_rtt),
                                icmpType,
                                icmpCode,
                                addr[0]
                            )
                            )
                        # Reset rtt_list for next ping.
                        rtt_list = []

                    elif icmpType == 0 and packet_num == 3:  # Echo Reply
                        min_rtt = min(rtt_list)
                        max_rtt = max(rtt_list)
                        avg_rtt = sum(rtt_list) / len(rtt_list)
                        print(
                            "  TTL=%d    MinRTT=%.0f ms    MaxRTT=%.0f ms    AvgRTT=%.0f ms    Type=%d    Code=%d    %s" %
                            (
                                ttl,
                                int(min_rtt),
                                math.ceil(max_rtt),
                                int(avg_rtt),
                                icmpType,
                                icmpCode,
                                addr[0]
                            )
                        )
                        # Reset rtt_list for next ping.
                        rtt_list = []

                        global ping_complete
                        ping_complete = True  # Set ping_complete to True to cease loop in __sendIcmpTraceRoute
                        return  # Echo reply is the end and therefore should return

                    else:
                        return
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket
            self.__IcmpIdentifier_isValid = None

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpIdentifier_isValid(self):
            # Get a boolean value that indicates whether the reply packet is valid or not.
            return self.__IcmpIdentifier_isValid

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # Return raw data, which may include ignored invalid bytes.
            try:
                self.__recvPacket[36:].decode('utf-8')
            except UnicodeDecodeError:
                return self.__recvPacket[36:].decode('utf-8', errors='ignore')
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            # Set whether the reply packet is valid or not with a boolean value.
            self.__IcmpIdentifier_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printPingResultToConsole(self, packet_num):
            # Increment packets_sent or packets_dropped under "Public Variables" depending on the echo reply status.
            global packets_sent, packets_dropped
            if self.getIcmpIdentifier_isValid() is True:
                packets_sent += 1
            else:
                packets_dropped += 1

            # After the final echo reply, print cumulative ping data and packet loss data.
            if packet_num == 3:
                global rtt_list
                min_rtt = min(rtt_list)
                max_rtt = max(rtt_list)
                avg_rtt = sum(rtt_list) / len(rtt_list)
                packet_loss = (packets_dropped/(packets_sent+packets_dropped)) * 100
                print("-----------------------------------------------------------------")
                print("Ping Statistics")
                print("-----------------------------------------------------------------")
                print("  MinRTT=%d ms    MaxRTT=%d ms    AvgRTT=%d ms    PacketLoss=%d" %
                        (
                            int(min_rtt),
                            math.ceil(max_rtt),
                            int(avg_rtt),
                            packet_loss
                        )
                      )
                print("-----------------------------------------------------------------")

                # Reset variables for next ping.
                rtt_list = []
                packets_sent = 0
                packets_dropped = 0

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                 # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        print_ping_target = 0
        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            if print_ping_target == 0:
                icmpPacket.printPingTarget()  # Call printPingTarget() to print target details.
                print_ping_target += 1
            icmpPacket.sendPingEchoRequest(30, i)  # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        print_ping_target = 0
        for ttl in range(1, 256):
            # Check ping_complete under "Public Variables" to determine if another increase in TTL is required.
            global ping_complete
            if ping_complete is False:
                for i in range(4):
                    # Build packet
                    icmpPacket = IcmpHelperLibrary.IcmpPacket()

                    randomIdentifier = (
                                os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
                    # Some PIDs are larger than 16 bit

                    packetIdentifier = randomIdentifier
                    packetSequenceNumber = i

                    icmpPacket.buildPacket_echoRequest(packetIdentifier,
                                                       packetSequenceNumber)  # Build ICMP for IP payload
                    icmpPacket.setIcmpTarget(host)
                    if print_ping_target == 0:
                        icmpPacket.printTracerouteTarget()  # Call printTracerouteTarget() to print target details.
                        print_ping_target += 1
                    icmpPacket.sendTraceEchoRequest(ttl, i)  # Build IP

                    icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                    icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                    # we should be confirming values are correct, such as identifier and sequence number and data

        # Signal the traceroute target by printing the target's name and IP address.
        print("-------------------------------------------------------------------------------------------------------------------------")
        print("Traceroute complete.")
        print("-------------------------------------------------------------------------------------------------------------------------")

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("200.10.227.250")
    # icmpHelperPing.sendPing("110.33.122.75")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("81.2.69.192")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("200.10.227.250")
    icmpHelperPing.traceRoute("62.1.205.50")


if __name__ == "__main__":
    main()
