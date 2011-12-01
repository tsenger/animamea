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

import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class AmCardHandler {
	
	private Card card = null;
	private CardChannel channel = null;
	
	public ResponseAPDU transceive(CommandAPDU capdu) throws CardException {
		System.out.println("<"+HexString.bufferToHex(capdu.getBytes()));
		ResponseAPDU resp = channel.transmit(capdu);
		System.out.println(">"+HexString.bufferToHex(resp.getBytes())+"\n");
		return resp;
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
