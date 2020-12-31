/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package il.ac.idc.cs.sinkhole;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.nio.ShortBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import jdk.jfr.Unsigned;


/**
 *
 * @author david
 */
public class DNSParser {
    
    class Flags
    {
        private short flags;
        
        short reverse(short x)
        {
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.order(ByteOrder.BIG_ENDIAN);
            bb.putShort(x);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            return bb.getShort(0);
        }
        
        boolean isBitSet(int n, int k) 
        { 
            return ((n & (1L << k-1)) != 0);
        } 

        void setBit(int k) 
        { 
            flags |= 1 << k-1;
        } 

        void unsetBit(int k) 
        { 
            flags &= ~(1 << k-1);
        }         
        
        void setOpCode(int val)
        {
            short OpCodeMask = 0x7800;
            // clear original
            flags &= (short)(~(OpCodeMask));
            // set new value
            flags |= (short)(val << 11); 
        }
        
	void setRCode(int val)
        {
            short RCodeMask = 0x000F;
            // clear original
            flags &= (short)(~(RCodeMask));
            // set new value
            flags |= (short)val;
	}
        
        Flags(short flags)
        {
            this.flags = flags;
        }

        boolean isQuery()
        {  
            return isBitSet(flags, 16);
        }
        
        void setQR(boolean b)
        {
            if(b)
                setBit(16);
            else
                unsetBit(16);
        }
        
        short getOpCode()
        {
            return (short)((flags & 0x7800) >> 11);
        }
        
        boolean isAA()
        {
            return isBitSet(flags, 11);
        }

        boolean isTC()
        {
            return isBitSet(flags, 10);
        }

        boolean isRD()
        {
            return isBitSet(flags, 9);
        }

        void setRD(boolean b)
        {
            if(b)
                setBit(9);
            else
                unsetBit(9);
        }

        boolean isRA()
        {
            return isBitSet(flags, 8);
        }

        void setRA(boolean b)
        {
            if(b)
                setBit(8);
            else
                unsetBit(8);
        }
        
        short getRCode()
        {
            return (short)(flags & 0x000F);
        }
        
        String asString()
        {
            return "0x" + String.format("%x", flags);
        }
    }

    class Query
    {
        public String host = new String();
        public short qtype = 0;
        public short qclass = 0;
        
        public String asString()
        {
            StringBuffer sb = new StringBuffer();
            sb.append("Host [").append(host).append("] QTYPE[");
            sb.append(qtype).append("] QCLASS[").append(qclass).append("]");
            return sb.toString();
        }
    }
    
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
    
    DNSParser(DatagramPacket packet)
    {
        this.packet = packet;
        bb = ByteBuffer.wrap(packet.getData());
        flags = new Flags(bb.getShort(2));
        query = null;         
        RRList = new ArrayList<RR>();
    }
    
    DatagramPacket getUpdatedPacket(short rcode)
    {
        flags.setRCode(rcode);
        bb.putShort(2, flags.flags);
        return packet;
    }
    
    boolean isValidRequest()
    {
        /* for a request to be valid, 
            - num of queestions has to be > 0
            - type has to be A
            - class has to be IN
        */
        boolean rc = false;
        
        if(getNumQuestions() <= 0)
            System.err.println("Inbound request has no question\n");
            
        return true;
    }
    
    Flags getFlags()
    {
        return flags;
    }
    
    short getNumQuestions()
    {
        return bb.getShort(4);
    }
        
    short getNumAnswers()
    {
        return bb.getShort(6);
    }

    short getNumAuthorities()
    {
        return bb.getShort(8);
    }

    short getID() 
    {
        return bb.getShort(0);
    }
    
    void setID(short id)
    {
        bb.putShort(0, id);
    }
    
    Query getQuestion() 
    { 
        return query; 
    }
    
    List<RR> getRRList() 
    { 
        return RRList; 
    }

    void getLabels(int currPos, ReadDNSResult r) 
    {       
        byte firstByte = 0;
        
        while (true) {           
            
            firstByte = bb.get(currPos);
            
            // check if this is a regular label
            if( ( (firstByte & COMPRESSION_MASK) == 0) && firstByte > 0)
            {
                currPos++;            
                byte[] record = new byte[firstByte];
                for (int i = 0; i < firstByte; i++) {
                    record[i] = bb.get(currPos);
                    currPos++;
                }            
                //r.host = r.host + new String(record, "UTF-8") + new String(".");                
                r.host = r.host + new String(record, StandardCharsets.UTF_8) + new String(".");
            }
            else if(firstByte == 0)
            {
                r.currPos = currPos + 1;                
                // remove last .
                if( r.host.charAt(r.host.length()-1) == '.')
                    r.host = r.host.substring(0, r.host.length() - 1);
                break;                
            } else { // this is a pointer
                currPos++;
                byte secondByte = bb.get(currPos);
                currPos++;
                short offset = 0;
                offset |= (firstByte << 8);
                offset |= secondByte;
                offset &= ~(COMPRESSION_MASK);
                getLabels(offset, r);
                r.currPos = currPos;
                break;
            }
        }
    }
    
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
    
    /*
        read the name.  If this is a pointer, get get the data wherever it is pointed to
        read the type, class, ttl, rdlength and rddata
    */
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
            
            if(rr.type == 1) // this is an A record
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
            else if (rr.type == 2) // this is an NS record
            {
                r = new ReadDNSResult();
                getLabels(currPos, r);
                rr.hostname = r.host;
                currPos = r.currPos;
            }
            else
            {
                // Barf!
            }
            
            RRList.add(rr);
        }
        
        return currPos;
    }
    
    void parseDNS() 
    {
        // start reading question section
        int currPos = getInternalQuery();
        
        // now start reading next sections
        if(getNumAnswers() > 0)  // this section is an answer
        {
            currPos = getRR(currPos, getNumAnswers());
            return;
        }
        
        // another one?
        if(getNumAuthorities() > 0) // this section is an authority(list)
        {
            currPos = getRR(currPos, getNumAuthorities());
        }
    }
    
    InetAddress getAddress() { return packet.getAddress(); }
    void setAddress(InetAddress addr) { packet.setAddress(addr); }
    int getPort() { return packet.getPort(); }
    void setPort(int port) { packet.setPort(port); }
}
