package de.tsenger.animamea;

import de.tsenger.animamea.asn1.bc.SecurityInfos;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.tools.HexString;

/**
*
* @author Tobias Senger (tobias@t-senger.de)
*/
public class Operator {

	static byte[] fid = new byte[]{(byte) 0x01, (byte)0x1C};
	static byte sfid = (byte)0x1C;
  
  
   public static void main(String[] args) throws Exception {
       
	   AmCardHandler ch = new AmCardHandler();
	   ch.connect(0); // First terminal
	   
	   FileAccess facs = new FileAccess(ch);
	   
	   
	   byte[] efcaBytes = facs.getFile(fid);
	   System.out.println(HexString.bufferToHex(efcaBytes));
	   
	   SecurityInfos si = new SecurityInfos();
	   si.decode(efcaBytes);
	   
	   System.out.println(si);
	   
   }

	

}
