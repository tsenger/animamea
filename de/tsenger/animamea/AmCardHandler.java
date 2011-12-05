/**
 * 
 */
package de.tsenger.animamea;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmCardHandler {
	
	private Card card = null;
	private CardChannel channel = null;
	private boolean debug = false;
	private SecureMessaging sm = null;
	
	public ResponseAPDU transceive(CommandAPDU capdu) throws Exception {
		if (debug) System.out.println("plain C-APDU:\n"+HexString.bufferToHex(capdu.getBytes()));
		if (sm!=null)capdu = sm.wrap(capdu);
		if ((debug)&&(sm!=null)) System.out.println("potected C-APDU:\n"+HexString.bufferToHex(capdu.getBytes()));
		
		ResponseAPDU resp = channel.transmit(capdu);
		
		if ((debug)&&(sm!=null)) System.out.println("potected R-APDU:\n"+HexString.bufferToHex(resp.getBytes()));
		if (sm!=null) resp = sm.unwrap(resp);
		if (debug) System.out.println("plain R-APDU:\n"+HexString.bufferToHex(resp.getBytes())+"\n");
		return resp;
	}
	
	/** Bei eingeschaltetem Debug-Modus werden alle CAPDU und RAPDU auf der Konsole ausgegeben.
	 * @param b
	 */
	public void setDebugMode(boolean b) {
		this.debug = b;
	}
	
	public void setSecureMessaging(SecureMessaging sm) {
		this.sm = sm;
	}
	
	/** Establish connection to terminal and card on terminal.
	 * @param index Number of the terminal to use
	 * @return connect successfull ?
	 * @throws CardException
	 */
	public boolean connect(int index) throws CardException {
	      
	       /* Is a Reader connected we can access? */
	       if (TerminalFactory.getDefault().terminals().list().size() == 0) {
	           System.err.println("No reader present");
	           return false;
	       }
	      
	       /* Terminal we are working on */
	        CardTerminal terminal = TerminalFactory.getDefault().terminals().list().get(index);
	      
	       /* Is a card present? */
	       if (!terminal.isCardPresent()) {
	           System.err.println("No Card present!");
	           return false;
	       }
	      
	       card = terminal.connect("T=1");
	       channel = card.getBasicChannel();
	       return true;
	}
	
	public void disconnect() throws CardException {
		channel.close();
		card.disconnect(true);

	}
	
	public byte[] getATR() {
	       return card.getATR().getBytes();
	}


}
