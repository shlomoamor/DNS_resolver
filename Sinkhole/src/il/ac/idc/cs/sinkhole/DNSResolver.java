package il.ac.idc.cs.sinkhole;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

/** This class is responsible for resolving the DNS request implementing Runnable*/
public class DNSResolver implements Runnable {
    final static int DNS_QUERY_PORT = 53;
    final static int MAX_RETRIES = 16;
        
	SynchronizedQueue<DatagramPacket> queue;
    DatagramSocket socket;
    DNSBlockList blockList;
    DNSRootServer rootServers;
    short queryID;


    /** Class constructor.
     * @param queue Thread Queue
     * @param socket socket
     * @param blockList List of blocked Hostnames
     * @param rootServers the Root-server
     */
	public DNSResolver(SynchronizedQueue<DatagramPacket> queue, DatagramSocket socket, DNSBlockList blockList, DNSRootServer rootServers)
	{
		this.queue = queue;
        this.socket = socket;
        this.blockList = blockList;
        this.rootServers = rootServers;
        queryID = 1;
	}

    /** Builds a DNS Packet Request
     * @param query
     * @return dnsFrame
     */
    private byte[] buildDNSFrame(DNSParser.Query query) throws IOException
    {
        // Build a iterative query for the host sent by the client
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write ID;
        dos.writeShort(queryID++);

        // Write Query Flags
        dos.writeShort(0x0000);

        // Question Count: Specifies the number of questions in the Question section of the message.
        dos.writeShort(0x0001);

        // Answer Record Count: Specifies the number of resource records in the Answer section of the message.
        dos.writeShort(0x0000);

        // Authority Record Count: Specifies the number of resource records in the Authority section of
        // The message. NS stands for <name server>
        dos.writeShort(0x0000);

        // Additional Record Count: Specifies the number of resource records in the Additional section of the message.
        dos.writeShort(0x0000);

        String[] domainParts = query.host.split("\\.");

        // Write labels
        for (int i = 0; i < domainParts.length; i++) {
            byte[] domainBytes = domainParts[i].getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }

        // End of labels
        dos.writeByte(0x00);

        // Type 0x01 = A (Host Request)
        dos.writeShort(0x0001);

        // Class 0x01 = IN
        dos.writeShort(0x0001);

        byte[] dnsFrame = baos.toByteArray();

        return dnsFrame;
    }

    /** Resolve DNS Request and iteratively send reply
     * @param clientPacketParser packet parser object
     * @param query
     */
    private void resolveAndSendReply(DNSParser clientPacketParser, DNSParser.Query query) throws IOException
    {
        // Get a random ROOT dns server
        InetAddress destination = rootServers.getRandomRootServer();

        int count = 0;
        while(count < MAX_RETRIES)
        {
            // System.out.println("Running query " + count + " to " + destination.getHostName());

            // Build request
            byte[] dnsFrame = buildDNSFrame(query);

            // *** Send DNS Request Frame ***
            DatagramSocket dnsSocket = new DatagramSocket();
            DatagramPacket dnsReqPacket = new DatagramPacket(dnsFrame, dnsFrame.length, destination, DNS_QUERY_PORT);
            dnsSocket.send(dnsReqPacket);

            // Await response from DNS server
            byte[] buf = new byte[1024];
            DatagramPacket responePacket = new DatagramPacket(buf, buf.length);
            dnsSocket.receive(responePacket);

            DNSParser parser = new DNSParser(responePacket);
            parser.parseDNS();
            short rcode = parser.getFlags().getRCode();
            short answerRecords = parser.getNumAnswers();
            short authRecords = parser.getNumAuthorities();

            if(rcode != 0)
            {
                System.err.println("Received error " + rcode + " for request " + parser.getID());
                sendErrorReply(clientPacketParser, rcode);
                break;
            }
            // Got a resolved address?
            else if(answerRecords > 0)
            {
                /*
                // get the desired rr, ie, the A record
                DNSParser.RR rr = null;

                int k;
                for(k = 0; k < parser.getRRList().size(); k++)
                {
                    rr = parser.getRRList().get(k);
                    if(rr.type == 1)
                        break;
                }

                if(k == parser.getRRList().size())
                    rr = null;

                // get the address and return to our client
                // System.out.println("Got ip address of " + rr.address);
                */
                // Set the id to original id
                parser.setID(clientPacketParser.getID());

                // We now set the qr, rd and ra flags in the response packet
                parser.getFlags().setQR(true);
                parser.getFlags().setRD(true);
                parser.getFlags().setRA(true);
                // Remember to unset aa flag in the response packet
                parser.getFlags().setAA(false);

                // Then we set the address and host of the response packet to the original
                // Client's info
                parser.setAddress(clientPacketParser.getAddress());
                parser.setPort(clientPacketParser.getPort());

                // Finally send reply back to original client
                socket.send(parser.getUpdatedPacket((short)0));

                break;
            }
            // Got a authority record?
            else if(authRecords > 0)
            {
                // Get first authority record
                DNSParser.RR rr = parser.getRRList().get(0);
                destination = InetAddress.getByName(rr.hostname);
            }
            else
            {
                System.err.println("Interesting case!!\n");
                break;
            }

            count++;
        }

        if(count >= MAX_RETRIES)
        {
            System.err.println("Exceeded max retries for qname " + query.host);
            sendErrorReply(clientPacketParser, (short)5);
        }
    }

    /** Send an error reply
     * @param parser parser object
     * @param rcode error R-code for error reply
     */
    private void sendErrorReply(DNSParser parser, short rcode) throws IOException
    {
        // Send reply back to client
        socket.send(parser.getUpdatedPacket(rcode));
    }

    /** Runnnable implementation of Run*/
	public void run() {
            
		// System.out.println("Resolver thread starting...");
		
		while(true)
		{
                    DatagramPacket packet =  queue.dequeue();
                    if(packet == null)
                    {
                            // System.out.println("Request queue empty.  breaking...");
                            break;
                    }

                    // System.out.println("Got request from " + packet.getSocketAddress().toString());
                     /** Check that this is a request
                     * Check that this request is recursive
                     * In case of error, print error and reply back with RCODE REFUSED (5)**/
                    DNSParser parser = new DNSParser(packet);                    
                    short rcode = 0;

                    // Set QR to 1
                    parser.getFlags().setQR(true);

                    // Set RA to 1
                    parser.getFlags().setRA(true);                                        

                    if(!parser.getFlags().isQuery()) {
                        System.err.println("Packet is not query");                        
                        rcode = 5;
                    }
                    else if (!parser.getFlags().isRD()) {
                        System.err.println("Packet request is not recursive");                        
                        rcode = 5;
                    }
                    // Passed validation
                    else {
                        try {
                            parser.parseDNS();
                            DNSParser.Query q = parser.getQuestion();
                            if(q == null)
                            {
                                rcode = 5;
                            }
                            else
                            {
                                if(q.qclass != 1 || q.qtype != 1)
                                {
                                    System.err.println("Received invalid request for " + q.asString());
                                    rcode = 5;
                                }
                                else if(blockList.isBlocked(q.host))
                                {
                                    System.err.println("Received request for blocked host " + q.asString());
                                    rcode = 5;
                                }
                                else
                                {
                                    // Here we are actually ready to do some work
                                    resolveAndSendReply(parser, q);
                                }
                            }
                        } catch (IOException ex) {
                            System.err.println("Error: during run(): " + ex.getMessage());
                            System.err.println("\tIgnoring this request and back to processing queue");                            
                            continue;
                        }
                    }
                        
                    if(rcode != 0)
                    {
                        try {
                            // Return the packet to sender
                            sendErrorReply(parser, rcode);
                        } catch (IOException ex) {
                            System.err.println("Error: during run(): socket send: " + ex.getMessage());
                            System.err.println("\tIgnoring this request and back to processing queue");                            
                            continue;
                        }
                    }
		}	
		// System.out.println("Resolver thread exiting...");
	}

}
