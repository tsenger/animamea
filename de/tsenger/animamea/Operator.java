package de.tsenger.animamea;

import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.pace.PaceOperator;
import de.tsenger.animamea.tools.HexString;

/**
*
* @author Tobias Senger (tobias@t-senger.de)
*/
public class Operator {

	static final byte[] fid_efca = new byte[]{(byte) 0x01, (byte)0x1C};
	static final byte[] fid_efcs = new byte[]{(byte) 0x01, (byte)0x1D};
	static byte sfid = (byte)0x1C;
  
  
   public static void main(String[] args) throws Exception {
       
	   AmCardHandler ch = new AmCardHandler();
	   ch.setDebugMode(false);
	   ch.connect(0); // First terminal
	   
	   FileAccess facs = new FileAccess(ch);
	   byte[] efcaBytes = facs.getFile(fid_efca);
	   System.out.println(HexString.bufferToHex(efcaBytes));
	   
	   SecurityInfos si = new SecurityInfos();
	   si.decode(efcaBytes);
	   System.out.println(si);
	   
	   PaceOperator pop = new PaceOperator(ch);
	   pop.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 0);
	   long millis = System.currentTimeMillis();
	   SecureMessaging sm = pop.performPace();
	   if (sm!=null) {
		   System.out.println("time: "+(System.currentTimeMillis()-millis)+" ms");
		   System.out.println("PACE established!");
		   ch.setSecureMessaging(sm);
	   }   
//	   byte[] resetRetryCounter = Hex.decode("002c020306313233343536");
//	   ch.transceive(new CommandAPDU(resetRetryCounter));
//	   pop.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 0);
//	   pop.performPace();
	   
	   
//	   byte[] efcsBytes = facs.getFile(fid_efcs);
//	   System.out.println(HexString.bufferToHex(efcsBytes));
	   
	   
   }

	

}
