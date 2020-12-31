package il.ac.idc.cs.sinkhole;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;


public class SinkholeServer {

    final private static int WORKER_THREAD_COUNT = 1;
    final private static int SINKHOLE_PORT = 5300;
    
    public static void main(String[] args) {
        
        String blockListFilename = null;
        
        if(args.length == 1) {
            blockListFilename = args[0];
        }
        
        DNSBlockList blockList = null;
        try {
            blockList = new DNSBlockList(blockListFilename);
        } catch (IOException ex) {
            System.err.println("Error: Block list file \"" + blockListFilename + "\" does not exists or can't be read.");
            System.exit(1);
        }
        
        DNSRootServer rootServers = new DNSRootServer();
                
        // create a datagram socket on the right port
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(SINKHOLE_PORT);
        } catch (SocketException ex) {
            // Logger.getLogger(SinkholeServer.class.getName()).log(Level.SEVERE, null, ex);

            System.err.println("Socket error: " + ex.getMessage());
            System.exit(1);

        }
        
        // create a queue
        SynchronizedQueue<DatagramPacket> packetQueue = new SynchronizedQueue<>(WORKER_THREAD_COUNT);
        
        packetQueue.registerProducer();

        // start resolver threads
        for(int i=0; i < WORKER_THREAD_COUNT; i++)
            (new Thread(new DNSResolver(packetQueue, socket, blockList, rootServers))).start();
            
        while (true) {            
            // wait for a dns request
            byte buffer[] = new byte[1024];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            } catch (IOException ex) {
                System.err.println("Socket read error: " + ex.getMessage());
                continue;                
            }
            
            // push it into the queue
            packetQueue.enqueue(packet);
        }        
    }
}

