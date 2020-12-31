/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package dnsclient;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author david
 */
public class DNSBlockList {

    private Set<String> blockListSet;
    
    public DNSBlockList(String filename) throws FileNotFoundException, IOException {

        blockListSet = new HashSet<String>();
        
        if(filename == null) {
            return;
        }
        
        File file = new File(filename);
        BufferedReader br = new BufferedReader(new FileReader(file));
        
        String str;
        while((str = br.readLine()) != null) {
            blockListSet.add(str);
        }
    }
    
    public boolean isBlocked(String hostname) {
        boolean rc = false;
        
        if(!blockListSet.isEmpty())
        {
            if(blockListSet.contains(hostname))
                rc = true;
        }
        
        return rc;
    }
    
}
