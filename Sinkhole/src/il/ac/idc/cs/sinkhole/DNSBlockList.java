package il.ac.idc.cs.sinkhole;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** This class is responsible for loading the Blocked-List.txt into a set*/
public class DNSBlockList {

    private Set<String> blockListSet;
    /** Creates a hostname blocked list.
     * @param filename Blocked list file name.
     */
    public DNSBlockList(String filename) throws  IOException {
        blockListSet = new HashSet<String>();
        // No file was passed as an argument and therefore, the set remains empty
        if(filename == null) {
            return;
        }
        // We have a filename so create a new file instance
        File file = new File(filename);
        BufferedReader br = new BufferedReader(new FileReader(file));

        // Add each element (Website) to our set
        String str;
        while((str = br.readLine()) != null) {
            blockListSet.add(str);
        }
    }

    /** Checks if a given hostname is in the blocked set.
     * @param hostname The host website we are checking for.
     * @return A boolean indication of if the hostname is blocked
     */
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
