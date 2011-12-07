/**
 *  Copyright 2011, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.animamea;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
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

	/**
	 * Sendet die übergebene CommandAPDU an die konnektierte Karte. 
	 * Falls SecureMessaging initilisiert und gesetzt ist wird die APDU vor dem
	 * Senden SM-geschützt. Die empfangende APDU wird SM befreit und zurückgegeben.
	 * @param capdu Plain Command-APDU
	 * @return plain Response-APDU
	 * @throws CardException 
	 * @throws IOException 
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws ShortBufferException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws DataLengthException 
	 * @throws InvalidKeyException 
	 * @throws SecureMessagingException 
	 */
	public ResponseAPDU transceive(CommandAPDU capdu) throws CardException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, IOException, SecureMessagingException {
		if (debug)
			System.out.println("plain C-APDU:\n"
					+ HexString.bufferToHex(capdu.getBytes()));
		if (sm != null)
			capdu = sm.wrap(capdu);
		if ((debug) && (sm != null))
			System.out.println("potected C-APDU:\n"
					+ HexString.bufferToHex(capdu.getBytes()));

		ResponseAPDU resp = channel.transmit(capdu);

		if ((debug) && (sm != null))
			System.out.println("potected R-APDU:\n"
					+ HexString.bufferToHex(resp.getBytes()));
		if (sm != null)
			resp = sm.unwrap(resp);
		if (debug)
			System.out.println("plain R-APDU:\n"
					+ HexString.bufferToHex(resp.getBytes()) + "\n");
		return resp;
	}
	

	/**
	 * Bei eingeschaltetem Debug-Modus werden alle CAPDU und RAPDU auf der
	 * Konsole ausgegeben.
	 * 
	 * @param b
	 */
	public void setDebugMode(boolean b) {
		this.debug = b;
	}

	/**
	 * Aktiviert das SecureMessaging für alle nachfolgenden transceive-Aufrufe.
	 * @param sm initialisiertes SecureMessaging-Objekt
	 */
	public void setSecureMessaging(SecureMessaging sm) {
		this.sm = sm;
	}

	/**
	 * Establish connection to terminal and card on terminal.
	 * 
	 * @param index
	 *            Number of the terminal to use
	 * @return connect Connection successfull ?
	 * @throws CardException
	 */
	public boolean connect(int index) throws CardException {

		/* Is a Reader connected we can access? */
		if (TerminalFactory.getDefault().terminals().list().size() == 0) {
			System.err.println("No reader present");
			return false;
		}

		/* Terminal we are working on */
		CardTerminal terminal = TerminalFactory.getDefault().terminals().list()
				.get(index);

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
