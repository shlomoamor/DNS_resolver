package dnsclient;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DNSResolver implements Runnable {

        final static int DNS_QUERY_PORT = 53;
        final static int MAX_RETRIES = 16;
        
	SynchronizedQueue<DatagramPacket> queue;
        DatagramSocket socket;
        DNSBlockList blockList;
        DNSRootServer rootServers;
        short queryID;
	
	public DNSResolver(SynchronizedQueue<DatagramPacket> queue, DatagramSocket socket, DNSBlockList blockList, DNSRootServer rootServers)
	{
		this.queue = queue;
                this.socket = socket;
                this.blockList = blockList;
                this.rootServers = rootServers;
                queryID = 1;
	}
        
        private byte[] buildDNSFrame(DNSParser.Query query) throws IOException
        {
            // build a iterative query for the host sent by the client
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
            // the message. (“NS” stands for “name server”)
            dos.writeShort(0x0000);

            // Additional Record Count: Specifies the number of resource records in the Additional section of the message.
            dos.writeShort(0x0000);

            String[] domainParts = query.host.split("\\.");

            // write labels
            for (int i = 0; i < domainParts.length; i++) {
                byte[] domainBytes = domainParts[i].getBytes("UTF-8");
                dos.writeByte(domainBytes.length);
                dos.write(domainBytes);
            }

            // end of labels
            dos.writeByte(0x00);

            // Type 0x01 = A (Host Request)
            dos.writeShort(0x0001);

            // Class 0x01 = IN
            dos.writeShort(0x0001);

            byte[] dnsFrame = baos.toByteArray();
            
            return dnsFrame;
        }        
        
        private void resolveAndSendReply(DNSParser clientPacketParser, DNSParser.Query query) throws IOException
        {
            // get a random ROOT dns server
            InetAddress destination = rootServers.getRandomRootServer();

            int count = 0;
            while(count < MAX_RETRIES)
            {
                System.out.println("Running query " + count + " to " + destination.getHostName());
                
                // build request
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
                else if(answerRecords > 0) // got a resolved address?
                {
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
                    System.out.println("Got ip address of " + rr.address);
                    
                    // set the id to original id
                    parser.setID(clientPacketParser.getID());
                    
                    // we now set the qr, rd and ra flags in the response packet
                    parser.getFlags().setQR(true);
                    parser.getFlags().setRD(true);
                    parser.getFlags().setRA(true);
                    
                    // then we set the address and host of the response packet to the original
                    // client's info
                    parser.setAddress(clientPacketParser.getAddress());
                    parser.setPort(clientPacketParser.getPort());
                            
                    // finally send reply back to original client
                    socket.send(parser.getUpdatedPacket((short)0));
                    
                    break;
                }
                else if(authRecords > 0) // got a authority record?
                {
                    // get first authority record
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
        
        private void sendErrorReply(DNSParser parser, short rcode) throws SocketException, IOException
        {                                   
            // send reply back to client
            socket.send(parser.getUpdatedPacket(rcode));
        }
	        
	public void run() {
            
		System.out.println("Resolver thread starting...");
		
		while(true)
		{
                    DatagramPacket packet =  queue.dequeue();
                    if(packet == null)
                    {
                            System.out.println("Request queue empty.  breaking...");
                            break;
                    }

                    System.out.println("Got request from " + packet.getSocketAddress().toString());

                    // check that this is a request
                    // check that this request is recursive
                    // in case of error, print error and reply back with RCODE REFUSED (5)
                    DNSParser parser = new DNSParser(packet);                    
                    short rcode = 0;

                    // set QR to 1
                    parser.getFlags().setQR(true);

                    // set RA to 1
                    parser.getFlags().setRA(true);                                        

                    if(!parser.getFlags().isQuery()) {
                        System.err.println("Packet is not query");                        
                        rcode = 5;
                    }
                    else if (!parser.getFlags().isRD()) {
                        System.err.println("Packet request is not recursive");                        
                        rcode = 5;
                    }
                    else {
                        // passed validation
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
                                    // here we are actually ready to do some work
                                    resolveAndSendReply(parser, q);
                                }
                            }
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(DNSResolver.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(DNSResolver.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                        
                    if(rcode != 0)
                    {
                        try {
                            // return the packet to sender
                            sendErrorReply(parser, rcode);
                        } catch (IOException ex) {
                            Logger.getLogger(DNSResolver.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
		}	
		
		System.out.println("Resolver thread exiting...");
	}

}
