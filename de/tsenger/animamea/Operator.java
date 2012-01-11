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

	static final byte[] fid_efca = new byte[] { (byte) 0x01, (byte) 0x1C };
	static final byte[] fid_efcs = new byte[] { (byte) 0x01, (byte) 0x1D };
	static byte sfid = (byte) 0x1C;

	public static void main(String[] args) throws Exception {

		AmCardHandler ch = new AmCardHandler();
		ch.setDebugMode(true);
		ch.connect(0); // First terminal

		FileAccess facs = new FileAccess(ch);
		long millis = System.currentTimeMillis();
		
		//Lese Inhalt des EF.CardAccess
		byte[] efcaBytes = facs.getFile(fid_efca);
		System.out.println(HexString.bufferToHex(efcaBytes));

		//Parse den Inhalt des EF.CardAccess
		SecurityInfos si = new SecurityInfos();
		si.decode(efcaBytes);
		System.out.println(si);

		//Initialisiere PACE mit dem ersten PACE-Info aus dem EF.CardAccess
		//PIN: 123456, Passwort-Referenz 3=PIN, Terminaltyp 2=AuthenticationTerminal
		PaceOperator pop = new PaceOperator(ch);
	
		if (si.getPaceDomainParameterInfoList().size()>0) //Properitäre PACE Domain-Paramter vorhanden
		pop.setAuthTemplate(si.getPaceInfoList().get(0), si.getPaceDomainParameterInfoList().get(0), "276884", 2, 2);
		else pop.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 2); //Standardisierte PACE Domain Paramter
		
		//Führe PACE durch
		SecureMessaging sm = pop.performPace();
		
		//Wenn PACE erfolgreich durchgeführt wurde, wird sein SecureMessaging-Objekt
		//mit gültigen Session-Keys zurückgeliefert.
		if (sm != null) {
			System.out.println("time: " + (System.currentTimeMillis() - millis)
					+ " ms");
			System.out.println("PACE established!");
			ch.setSecureMessaging(sm);
		}
		// byte[] resetRetryCounter = Hex.decode("002c020306313233343536");
		// ch.transceive(new CommandAPDU(resetRetryCounter));
		// pop.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 0);
		// pop.performPace();

		// byte[] efcsBytes = facs.getFile(fid_efcs);
		// System.out.println(HexString.bufferToHex(efcsBytes));

	}

}
