package de.bund.bsi.animamea.iso7816;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.smartcardio.CommandAPDU;


public class CardCommands {
	

	private CardCommands() {
	}
	

	public static CommandAPDU readBinary(byte sfid, byte readlength) throws Exception{
		if (sfid>0x1F) throw new Exception("Invalid Short File Identifier!");
		byte P1 = (byte) 0x80;
		P1=(byte) (P1|sfid);
		return new CommandAPDU(new byte[] {0, (byte)0xB0, P1, 0, readlength});
	}
	
	
	public static CommandAPDU readBinary(byte high_offset, byte low_offset, byte le){        
        byte[] command = {(byte)0x00, (byte)0xB0, high_offset, low_offset, le};
        return new CommandAPDU(command);        
    }
	
	public static CommandAPDU selectEF(byte[] fid) {
		byte[] selectCmd = new byte[]{(byte)0x00, (byte)0xA4, (byte)0x02, (byte)0x0C};
		ByteArrayOutputStream command = new ByteArrayOutputStream(); 
		try {
			command.write(selectCmd);
			command.write(fid.length);
			command.write(fid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}	
		return new CommandAPDU(command.toByteArray());
	}
		
	public static CommandAPDU selectApp(byte[] aid) {
		byte[] selectCmd = new byte[]{(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x0C};
		ByteArrayOutputStream command = new ByteArrayOutputStream(); 
		try {
			command.write(selectCmd);
			command.write(aid.length);
			command.write(aid);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		return new CommandAPDU(command.toByteArray());
	}
	
	

	

}
