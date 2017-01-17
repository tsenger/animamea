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
package de.tsenger.sandbox;

import java.math.BigInteger;

import javax.smartcardio.CardException;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.Operator;
import de.tsenger.animamea.asn1.PaceInfo;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.pace.PaceException;
import de.tsenger.animamea.pace.PaceOperator;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class CapaceTest {

	private AmCardHandler ch = null;
	private final FileAccess facs = null;

	static Logger logger = Logger.getLogger(Operator.class);

	/**
	 * @param args
	 * @throws CardException 
	 * @throws PaceException 
	 * @throws SecureMessagingException 
	 */
	public static void main(String[] args) throws PaceException, CardException, SecureMessagingException {

		PropertyConfigurator.configure("log4j.properties");
		logger.info("Entering application.");

		CapaceTest capace = new CapaceTest();
		capace.performPACE();
	}

	public CapaceTest() throws SecureMessagingException, CardException {
		connectCard();
		//Selektiere die CaPACE Anwendung
//		ch.transceive(CardCommands.selectApp(Hex.decode("D2760001324361504345")));
	}
	
	private void test() {
		BigInteger a;
		BigInteger b;
	}

	public void performPACE() throws PaceException, CardException {
		PaceOperator pop = new PaceOperator(ch);
		
		// We didn't read EF.CardAccess, but build our own PACEInfo
		// OID for id_PACE-CAM AES CBC CMAC 128
		PaceInfo pi = new PaceInfo("0.4.0.127.0.7.2.2.6.2.2", 2, 0xd);
		pop.setAuthTemplate(pi, "500540", 2, 1);

		// Führe id_PACE durch
		SecureMessaging sm = null;
		try {
			sm = pop.performPace(null);
		} catch (SecureMessagingException e) {
			throw new PaceException("SecureMessaging failure while performing id_PACE", e);
		} 
	}

	private void connectCard() {

		// CardHandler erzeugen und erstes Terminal verbinden
		ch = new AmCardHandler();

		try {
			if (!ch.connect(0)) // 0 = First terminal
			{
				logger.error("Can't connect to card!");
				System.exit(0);
			}
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	}

}
