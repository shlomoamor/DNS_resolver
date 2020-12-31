/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package il.ac.idc.cs.sinkhole;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Random;

/**
 *
 * @author david
 */
public class DNSRootServer {
    
    final private static int NUM_ROOT_SERVERS = 13;
    
    private class ServerInfo {

        public ServerInfo(String name, String strAddress) {
            this.name = name;
            try {
                this.address = InetAddress.getByName(strAddress);
            } catch (UnknownHostException ex) {
                Logger.getLogger(DNSRootServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        String      name;
        InetAddress address;
    }

    private ServerInfo[] servers;
    private Random rand;
    
    public DNSRootServer() {
        servers = new ServerInfo[NUM_ROOT_SERVERS];
        
        servers[0] = new ServerInfo("a.root-servers.net", "198.41.0.4");
        servers[1] = new ServerInfo("b.root-servers.net", "199.9.14.201");
        servers[2] = new ServerInfo("c.root-servers.net", "192.33.4.12");
        servers[3] = new ServerInfo("d.root-servers.net", "199.7.91.13");
        servers[4] = new ServerInfo("e.root-servers.net", "192.203.230.10");
        servers[5] = new ServerInfo("f.root-servers.net", "192.5.5.241");
        servers[6] = new ServerInfo("g.root-servers.net", "192.112.36.4");
        servers[7] = new ServerInfo("h.root-servers.net", "198.97.190.53");
        servers[8] = new ServerInfo("i.root-servers.net", "192.36.148.17");
        servers[9] = new ServerInfo("j.root-servers.net", "192.58.128.30");
        servers[10] = new ServerInfo("k.root-servers.net", "193.0.14.129");
        servers[11] = new ServerInfo("l.root-servers.net", "199.7.83.42");
        servers[12] = new ServerInfo("m.root-servers.net", "202.12.27.33");        
        
        rand = new Random();
    }
    
    public InetAddress getRandomRootServer() {
        int idx = rand.nextInt(NUM_ROOT_SERVERS);
        return servers[idx].address;
    }   
}
