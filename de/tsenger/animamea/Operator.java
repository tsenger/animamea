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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.ca.CAOperator;
import de.tsenger.animamea.iso7816.CardCommands;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.pace.PaceOperator;
import de.tsenger.animamea.ta.CertificateProvider;
import de.tsenger.animamea.ta.TAOperator;
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
		
		//CardHandler erzeugen und erstes Terminal verbinden
		AmCardHandler ch = new AmCardHandler();
		ch.setDebugMode(true);
		ch.connect(0); // First terminal

		// Klasse FileAccess bietet Methoden zum Dateizugriff
		FileAccess facs = new FileAccess(ch);
		
		long millis = System.currentTimeMillis();
		
		//Lese Inhalt des EF.CardAccess
		byte[] efcaBytes = facs.getFile(fid_efca);
		System.out.println("EF.CardAccess read\ntime: " + (System.currentTimeMillis() - millis)	+ " ms");
//		System.out.println("EF.CardAccess:\n"+HexString.bufferToHex(efcaBytes));

		//Parse den Inhalt des EF.CardAccess
		SecurityInfos efca = new SecurityInfos();
		efca.decode(efcaBytes);
		System.out.println("\nEF.CardAccess decoded\ntime: " + (System.currentTimeMillis() - millis)	+ " ms");
//		System.out.println(efca);

		//Initialisiere PACE mit dem ersten PACE-Info aus dem EF.CardAccess
		//PIN: 123456, Passwort-Referenz 3=PIN, Terminaltyp 2=AuthenticationTerminal
		PaceOperator pop = new PaceOperator(ch);
	
		if (efca.getPaceDomainParameterInfoList().size()>0) //Properitäre PACE Domain-Paramter vorhanden
			pop.setAuthTemplate(efca.getPaceInfoList().get(0), efca.getPaceDomainParameterInfoList().get(0), "276884", 2, 2);
		else pop.setAuthTemplate(efca.getPaceInfoList().get(0), "819955", 2, 2); //Standardisierte PACE Domain Paramter
		
		//Führe PACE durch
		SecureMessaging sm = pop.performPace();
		
		//Wenn PACE erfolgreich durchgeführt wurde, wird sein SecureMessaging-Objekt
		//mit gültigen Session-Keys zurückgeliefert.
		if (sm != null) {
			System.out.println("\nPACE established!\ntime: " + (System.currentTimeMillis() - millis)
					+ " ms");
			ch.setSecureMessaging(sm);
		}
		
		//Erzeuge neuen Terminal Authentication Operator und übergebe den CardHandler
		TAOperator top = new TAOperator(ch);
		
		//TA benötigt zur Berechnung des ephemeralen PCD public Key die DomainParameter für die CA
		DomainParameter dp = new DomainParameter(efca.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter());
		
		// TA ausführen, Rückgabe ist der ephemerale PCD Public Key
		
		top.initialize(new CertificateProvider(), dp, pop.getPKpicc());
		KeyPair ephPCDKeyPair = top.performTA();
		
		System.out.println("\nTA established!\ntime: " + (System.currentTimeMillis() - millis)	+ " ms");

		
		//Lese EF.CardSecurity
		byte[] efcsBytes = facs.getFile(fid_efcs);
		System.out.println("EF.CardSecurity read\ntime: " + (System.currentTimeMillis() - millis)	+ " ms");

		
		//Extrahiere SecurityInfos
		SecurityInfos efcs = decodeEFCardAccess(efcsBytes);
//		System.out.println("\nEF.CardSecurity \n: " + efcs);
		System.out.println("\nEF.CardSecurity decoded\ntime: " + (System.currentTimeMillis() - millis)	+ " ms");

		
		// Erzeuge Chip Authentication Operator und übergebe CardHandler
		CAOperator cop = new CAOperator(ch);
		
		//Initialisiere und führe CA durch
		cop.initialize(efcs.getChipAuthenticationInfoList().get(0), efcs.getChipAuthenticationPublicKeyInfoList().get(0), ephPCDKeyPair);
		SecureMessaging sm2 = cop.performCA();
		
		// Wenn CA erfolgreich war, wird ein neues SecureMessaging Object zurückgeliefert welches die neuen Schlüssel enthält
		if (sm2 != null) {
			System.out.println("\nCA established!\ntime: " + (System.currentTimeMillis() - millis)+ " ms");
			ch.setSecureMessaging(sm2);
		}
		
		//Selektiere die eID-Anwendung
		ch.transceive(CardCommands.selectApp(Hex.decode("E80704007F00070302")));
		
		// Lese eine Datengrupppe
		byte dgno = 4;
		byte[] dgdata= facs.getFile(dgno);
		DERApplicationSpecific derapp = (DERApplicationSpecific) DERApplicationSpecific.fromByteArray(dgdata);
		DERUTF8String name = (DERUTF8String) derapp.getObject();
		System.out.println("DG0"+dgno+": "+ name);
		
		userInput(ch);
		
//		saveToFile("/home/tsenger/Desktop/EFCardSecurity.bin", efcsBytes);
		
		// byte[] resetRetryCounter = Hex.decode("002c020306313233343536");
		// ch.transceive(new CommandAPDU(resetRetryCounter));
		// pop.setAuthTemplate(si.getPaceInfoList().get(0), "123456", 3, 0);
		// pop.performPace();

		// byte[] efcsBytes = facs.getFile(fid_efcs);
		// System.out.println(HexString.bufferToHex(efcsBytes));

	}
	
	
	// Nimmt CAPDU über die Konsole entgegen und sendet sie SM-geschützt zur Karte
	private static void userInput(AmCardHandler ch) {
		BufferedReader bin = new BufferedReader(new InputStreamReader(System.in));
		
		do {
			String cmd=null;
			try {
				System.out.print("[] <-- ");
				cmd = bin.readLine();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (cmd.equals("")) return;
			byte[] resp = null;
			try {
				resp = ch.transceive(new CommandAPDU(Hex.decode(cmd))).getBytes();
			} catch (SecureMessagingException e) {
				System.out.println("got a SecureMessaging Error");
			} catch (CardException e) {
				System.out.println("got a Card Error");
				e.printStackTrace();
			}
			System.out.println("[] --> "+HexString.bufferToHex(resp));
		} while(true);
	}
	
	private static SecurityInfos decodeEFCardAccess(byte[] data) throws IOException {
		ASN1Sequence asnSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
		ContentInfo contentInfo = new ContentInfo(asnSeq);
		DERSequence derSeq = (DERSequence) contentInfo.getContent();
		SignedData signedData = new SignedData(derSeq);;
		ContentInfo contentInfo2 = signedData.getEncapContentInfo();
		DEROctetString octString = (DEROctetString) contentInfo2.getContent();
		
		SecurityInfos si = new SecurityInfos();
		
		si.decode(octString.getOctets());
	
		return si;
	}
	
	/**Saves data with the name given in parameter efName into a local file.
    *
    * @param efName The Name of the file
    * @param data
    * @return Returns 'true' if the record were saved to a local file on hd.
    */
	private static boolean saveToFile(String fileName, byte[] data) {
		boolean success = false;		
		
		try {
			File file = new File(fileName);
			FileOutputStream fos;
			fos = new FileOutputStream( file );
			fos.write(data);
			fos.close();
			success = true;
		} 
		catch (FileNotFoundException e) {} 
		catch (IOException e) {}
		
		return success;
	} 

}
