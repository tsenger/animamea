package de.tsenger.sandbox;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import de.tsenger.animamea.tools.HexString;

public class Smart {

	static final int CM_IOCTL_GET_FEATURE_REQUEST = SCARD_CTL_CODE(3400);

	static boolean isWindows() {
		String os_name = System.getProperty("os.name").toLowerCase();
		if (os_name.indexOf("windows") > -1)
			return true;
		return false;
	}

	static int SCARD_CTL_CODE(int code) {
		int ioctl;
		if (isWindows()) {
			ioctl = (0x31 << 16 | code << 2);
		} else {
			ioctl = 0x42000000 + code;
		}
		return ioctl;
	}

	public static void main(String[] args) {
		try {
			// show the list of available terminals
			TerminalFactory factory = TerminalFactory.getDefault();
			List<CardTerminal> terminals = factory.terminals().list();
			// get the first terminal
			if (terminals.isEmpty()) {
				System.out.println("No terminals found!");
			} else {
				System.out.println("Terminals: " + terminals);
				CardTerminal terminal = terminals.get(0);
				// establish a connection with the card
				// Card card = terminal.connect("T=1");
				Card card = terminal.connect("DIRECT");
				System.out.println("card: " + card);
				byte[] ccidResp = card.transmitControlCommand(
						CM_IOCTL_GET_FEATURE_REQUEST, new byte[] {});
				System.out.println(HexString.bufferToHex(ccidResp));
				CardChannel channel = card.getBasicChannel();
//				channel.transmit(new CommandAPDU(new byte[]{0,1,2,3,4,5,6}));
				// disconnect
				card.disconnect(false);
			}
		} catch (Exception e) {
			System.err.println(e.getLocalizedMessage());
		}
	}
}