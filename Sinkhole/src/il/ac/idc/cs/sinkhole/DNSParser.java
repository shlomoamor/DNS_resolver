package il.ac.idc.cs.sinkhole;
import java.nio.ByteBuffer;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;


/** This class is responsible for the packet parsing
 * @params packet
 */
public class DNSParser
{
    /** This class is responsible for the complete data extraction and manipulation
     * of the flag section of a given packet
     * @params flags The 2-Byte section of the packet which contains the flag
     */
    class Flags
    {
        final private static int RA_BIT = 8;
        final private static int RD_BIT = 9;
        final private static int TC_BIT = 10;
        final private static int AA_BIT = 11;
        final private static int QR_BIT = 16;

        private short flags;

        /** Class constructor getting the flag as input */
        Flags(short flags)
        {
            this.flags = flags;
        }

        /** Checks if the k-th bit in n is 1 or 0.
         * @param n The integer.
         * @param k The index of the bit we are checking.
         * @return A boolean indication of if the bit is on or off
         */
        boolean isBitSet(int n, int k)
        { 
            return ((n & (1L << k-1)) != 0);
        }

        /** Sets the k-th bit of flags to 1.
         * @param k The index of the bit we are checking.
         */
        void setBit(int k) 
        { 
            flags |= 1 << k-1;
        }

        /** Sets the k-th bit of flags to 0.
         * @param k The index of the bit we are checking.
         */
        void unsetBit(int k) 
        { 
            flags &= ~(1 << k-1);
        }

        /** Sets Op-code to val.
         * @param val The value we want to change the op-code to.
         */
        void setOpCode(int val)
        {
            // 0111 1000 00..00
            short OpCodeMask = 0x7800;
            // Clear original
            flags &= (short)(~(OpCodeMask));
            // Set new value
            flags |= (short)(val << 11); 
        }

        /** Sets R-code to val.
         * @param val The value we want to change the R-code to.
         */
	    void setRCode(int val)
        {
            // 00..00 1111
            short RCodeMask = 0x000F;
            // Clear original
            flags &= (short)(~(RCodeMask));
            // Set new value
            flags |= (short)val;
	    }

        /** Sets QR to B.
         * @param b The value we want to change the QR to.
         */
        void setQR(boolean b)
        {
            if(b)
                setBit(QR_BIT);
            else
                unsetBit(QR_BIT);
        }

        /** Checks if the query bit is 1.
         * @return boolean indicator for the query bit.
         */
        boolean isQuery()
        {  
            return isBitSet(flags, QR_BIT);
        }

        /** Gets the op-code.
         * @return the op-code byte.
         */
        short getOpCode()
        {
            return (short)((flags & 0x7800) >> 11);
        }

        /** Gets the R-code.
         * @return the R-code byte.
         */
        short getRCode()
        {
            return (short)(flags & 0x000F);
        }

        /** Checks if the AA bit is 1.
         * @return boolean indicator for the AA bit.
         */
        boolean isAA()
        {
            return isBitSet(flags, AA_BIT);
        }

        /** Checks if the TC bit is 1.
         * @return boolean indicator for the TC bit.
         */
        boolean isTC()
        {
            return isBitSet(flags, TC_BIT);
        }

        /** Checks if the RD bit is 1.
         * @return boolean indicator for the RD bit.
         */
        boolean isRD()
        {
            return isBitSet(flags, RD_BIT);
        }

        /** Sets RD to B.
         * @param b The value we want to change the RD to.
         */
        void setRD(boolean b)
        {
            if(b)
                setBit(RD_BIT);
            else
                unsetBit(RD_BIT);
        }

        /** Checks if the ra bit is 1.
         * @return boolean indicator for the RA bit.
         */
        boolean isRA()
        {
            return isBitSet(flags, RA_BIT);
        }

        /** Sets RA to B.
         * @param b The value we want to change the RA to.
         */
        void setRA(boolean b)
        {
            if(b)
                setBit(RA_BIT);
            else
                unsetBit(RA_BIT);
        }


        
        String asString()
        {
            return "0x" + String.format("%x", flags);
        }
    }

    /** This class is responsible visualizing the host query*/
    class Query
    {
        public String host = new String();
        public short qtype = 0;
        public short qclass = 0;

        /** Builds a string visualization of the query
         * @return a string-builder with the full query
         */
        public String asString()
        {
            StringBuffer sb = new StringBuffer();
            sb.append("Host [").append(host).append("] QTYPE[");
            sb.append(qtype).append("] QCLASS[").append(qclass).append("]");
            return sb.toString();
        }
    }

    /** This class is responsible for the containment of a DNS resource record (RR)
     * An RR contains all the information about a domain name system.
     * It defines all the attributes for a domain name such as an IP address or a mail route.*/
    class RR
    {
        public String name = new String();
        public short type = 0;
        public short cls = 0;
        public long ttl = 0;
        public short rdlen = 0;
        public String hostname = new String();
        public String address = new String();
    }

    /** This class is responsible for keeping track of the current read-index position and string just read from the
     * readLabel method*/
    private class ReadDNSResult
    {
        int currPos;
        String host = new String();
    }
    
    private final byte COMPRESSION_MASK = (byte) 0xC0;     
    private DatagramPacket packet;
    private ByteBuffer bb;
    private Flags flags;
    private Query query;
    private List<RR> RRList;

    final private static int QUESTION_BYTE = 4;
    final private static int ANSWER_BYTE = 6;
    final private static int AUTHORITIES_BYTE = 8;
    final private static int ID_BYTE = 0;

    final private static int A_REC = 1;
    final private static int NS_REC = 2;


    /** Class constructor getting the packet as input */
    DNSParser(DatagramPacket packet)
    {
        this.packet = packet;
        bb = ByteBuffer.wrap(packet.getData());
        flags = new Flags(bb.getShort(2));
        query = null;         
        RRList = new ArrayList<RR>();
    }

    /** Change the R-code of the packet
     * @param rcode The new value for the R-code.
     * @return a new edited packet */
    DatagramPacket getUpdatedPacket(short rcode)
    {
        flags.setRCode(rcode);
        bb.putShort(2, flags.flags);
        return packet;
    }

    /** Checks if a request is valid, a valid request is:
     *              - num of questions has to be > 0
     *             - type has to be A
     *             - class has to be IN
     * @return a boolean indicator */
    boolean isValidRequest()
    {
        boolean rc = true;
        if(getNumQuestions() <= 0)
            System.err.println("Inbound request has no question\n");
        return rc;
    }

    /** Gets the Flag
     * @return flag object */
    Flags getFlags()
    {
        return flags;
    }

    /** Gets the QUESTION section
     * @return QUESTION short */
    short getNumQuestions()
    {
        return bb.getShort(QUESTION_BYTE);
    }

    /** Gets the ANSWER section
     * @return ANSWER short */
    short getNumAnswers()
    {
        return bb.getShort(ANSWER_BYTE);
    }

    /** Gets the AUTHORITIES section
     * @return AUTHORITIES short */
    short getNumAuthorities()
    {
        return bb.getShort(AUTHORITIES_BYTE);
    }

    /** Gets the ID section
     * @return ID short */
    short getID() 
    {
        return bb.getShort(ID_BYTE);
    }

    /** Change ID to id
     * @param id The new value for the id*/
    void setID(short id)
    {
        bb.putShort(0, id);
    }

    /** Gets the query section
     * @return query */
    Query getQuestion() 
    { 
        return query; 
    }

    /** Gets the RR List
     * @return RR List */
    List<RR> getRRList() 
    { 
        return RRList; 
    }

    /** Gets an entire label
     * @param currPos The index value to start reading from.
     * @param r where we store the currPoss or hostName */
    void getLabels(int currPos, ReadDNSResult r) 
    {       
        byte firstByte = 0;
        
        while (true) {           
            
            firstByte = bb.get(currPos);
            
            // Check if this is a regular label
            if( ( (firstByte & COMPRESSION_MASK) == 0) && firstByte > 0)
            {
                currPos++;            
                byte[] record = new byte[firstByte];
                for (int i = 0; i < firstByte; i++) {
                    record[i] = bb.get(currPos);
                    currPos++;
                }
                r.host = r.host + new String(record, StandardCharsets.UTF_8) + new String(".");
            }
            else if(firstByte == 0)
            {
                r.currPos = currPos + 1;                
                // Remove last . (full-stop)
                if( r.host.charAt(r.host.length()-1) == '.')
                    r.host = r.host.substring(0, r.host.length() - 1);
                break;                
            }
            // This is a pointer
            else {
                currPos++;
                byte secondByte = bb.get(currPos);
                currPos++;
                short offset = 0;
                offset |= (firstByte << 8);
                offset |= secondByte;
                offset &= ~(COMPRESSION_MASK);
                // Recursive call
                getLabels(offset, r);
                r.currPos = currPos;
                break;
            }
        }
    }

    /** Gets an entire label and populates the query object
     * @return currPos The index value to start reading from.*/
    int getInternalQuery() 
    {
        query = new Query();
        
        ReadDNSResult r = new ReadDNSResult();
        getLabels(12, r);

        query.host = r.host;
        query.qtype =  bb.getShort(r.currPos);
        r.currPos += 2;       
        query.qclass = bb.getShort(r.currPos);
        r.currPos += 2;
        return r.currPos;
    }

    /** Gets an RR label
     * @param currPos The index value to start reading from.
     * @param numRecords The amount of RR's we need to read */
    int getRR(int currPos, int numRecords) 
    {
        for(int i = 0; i < numRecords; i++)
        {
            ReadDNSResult r = new ReadDNSResult();
            getLabels(currPos, r);
            currPos = r.currPos;
            RR rr = new RR();
            rr.name = r.host;
            rr.type = bb.getShort(currPos);
            currPos += 2;
            rr.cls = bb.getShort(currPos);
            currPos += 2;
            rr.ttl = bb.getInt(currPos);
            currPos += 4;            
            rr.rdlen = bb.getShort(currPos);
            currPos += 2;

            // this is an A record
            if(rr.type == A_REC)
            {
                // rdlen should be 4 and this is an ip address
                if(rr.rdlen != 4)
                {
                    System.err.println("Type of RR is A but rdlen is " + rr.rdlen + "\n");
                }
                
                for (int j = 0; j < rr.rdlen; j++) {
                    rr.address = rr.address + (bb.get(currPos) & 0xFF);
                    if(j < rr.rdlen -1)
                        rr.address += ".";
                    currPos++;
                }                
            }
            // This is an NS record
            else if (rr.type == NS_REC)
            {
                r = new ReadDNSResult();
                getLabels(currPos, r);
                rr.hostname = r.host;
                currPos = r.currPos;
            }
            else
            {
                // Interesting case
                continue;
            }
            
            RRList.add(rr);
        }
        
        return currPos;
    }

    /** Parse DNS */
    void parseDNS() 
    {
        // Start reading question section
        int currPos = getInternalQuery();
        
        // Now start reading next sections
        if(getNumAnswers() > 0)  // this section is an answer
        {
            currPos = getRR(currPos, getNumAnswers());
            return;
        }

        if(getNumAuthorities() > 0) // this section is an authority(list)
        {
            currPos = getRR(currPos, getNumAuthorities());
        }
    }

    /** Get the packets address
     * @return packet address.*/
    InetAddress getAddress()
    {
        return packet.getAddress();
    }

    /** Set the packets address
     * @param addr The address we want to change the packet to*/
    void setAddress(InetAddress addr)
    {
        packet.setAddress(addr);
    }

    /** Get the packets port
     * @return packet port.*/
    int getPort()
    {
        return packet.getPort();
    }

    /** Set the packets port
     * @param port The port we want to change the packet to*/
    void setPort(int port)
    {
        packet.setPort(port);
    }
}
