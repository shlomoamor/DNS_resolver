package il.ac.idc.cs.sinkhole;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;

public class SinkholeServer {
    final private static int WORKER_THREAD_COUNT = 1;
    final private static int SINKHOLE_PORT = 5300;
    
    public static void main(String[] args) {
        
        String blockListFilename = null;
        // If file is passed in the command line
        if(args.length == 1) {
            blockListFilename = args[0];
        }

        // Create a new DNSBlockList with the the file passed int
        DNSBlockList blockList = null;
        try {
            blockList = new DNSBlockList(blockListFilename);
        }
        catch (IOException ex) {
            System.err.println("Error: Block list file \"" + blockListFilename + "\" does not exists or can't be read.");
            System.exit(1);
        }
        // Getting a random root server
        DNSRootServer rootServers = new DNSRootServer();
                
        // Create a datagram socket on the right port (Set above)
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(SINKHOLE_PORT);
        }
        catch (SocketException ex) {
            // Logger.getLogger(SinkholeServer.class.getName()).log(Level.SEVERE, null, ex);

            System.err.println("Socket error: " + ex.getMessage());
            System.exit(1);

        }
        // Create a Synchronized Queue for each request
        SynchronizedQueue<DatagramPacket> packetQueue = new SynchronizedQueue<>(WORKER_THREAD_COUNT);
        packetQueue.registerProducer();

        // Start resolver threads
        for(int i=0; i < WORKER_THREAD_COUNT; i++)
            (new Thread(new DNSResolver(packetQueue, socket, blockList, rootServers))).start();
            
        while (true) {            
            // Wait for a DNS request
            byte buffer[] = new byte[1024];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
            }
            catch (IOException ex) {
                System.err.println("Socket read error: " + ex.getMessage());
                continue;                
            }
            // Push the packet into the queue and let the threads do the work
            packetQueue.enqueue(packet);
        }        
    }
}

