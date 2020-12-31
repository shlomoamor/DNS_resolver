package dnsclient;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;


public class SinkholeServer {

    final private static int WORKER_THREAD_COUNT = 1;
    final private static int SINKHOLE_PORT = 5300;
    
    public static void main(String[] args) throws SocketException, IOException {
        
        String blockListFilename = null;
        
        if(args.length == 1) {
            blockListFilename = args[0];
        }
        
        DNSBlockList blockList = new DNSBlockList(blockListFilename);
        
        DNSRootServer rootServers = new DNSRootServer();
                
        // create a datagram socket on the right port
        DatagramSocket socket = new DatagramSocket(SINKHOLE_PORT);
        
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
            socket.receive(packet);
            
            // push it into the queue
            packetQueue.enqueue(packet);
        }        
    }
}

