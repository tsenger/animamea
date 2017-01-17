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
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;

import javax.smartcardio.CardException;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.asn1.SecurityInfos;
import de.tsenger.animamea.ca.CAOperator;
import de.tsenger.animamea.iso7816.CardCommands;
import de.tsenger.animamea.iso7816.FileAccess;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.pace.PaceException;
import de.tsenger.animamea.pace.PaceOperator;
import de.tsenger.animamea.ta.CertificateProvider;
import de.tsenger.animamea.ta.TAException;
import de.tsenger.animamea.ta.TAOperator;
import de.tsenger.animamea.tools.FileSystem;
import de.tsenger.animamea.tools.HexString;

/**
 * 
 * @author Tobias Senger <tobias@t-senger.de>
 */
public class Operator {

	static final byte[] FID_EFCardAccess = new byte[] { (byte) 0x01, (byte) 0x1C };
	static final byte[] FID_DIR = new byte[] { (byte) 0x2F, (byte) 0x00 };
	static final byte[] FID_ATR = new byte[] { (byte) 0x2F, (byte) 0x01 };
	static final byte[] FID_EFCardSec = new byte[] { (byte) 0x01, (byte) 0x1D };
	static final byte[] FID_EFChipSec = new byte[] { (byte) 0x01, (byte) 0x1B };
	static final byte SFID_EFCA = (byte) 0x1C;
	
	static final byte[] FID_SOD = new byte[] { (byte) 0x01, (byte) 0x1D };
	static final byte[] FID_DG1 = new byte[] { (byte) 0x01, (byte) 0x01 };

	static Logger logger = Logger.getLogger(Operator.class);
	
	private AmCardHandler ch = null;
	private FileAccess facs = null;
	private final String can = "098960";
	private final int slotID = 1; 
	

	public static void main(String[] args) throws Exception {
		
		PropertyConfigurator.configure("log4j.properties");
		
		logger.info("Entering application.");
		
		Operator op = new Operator();
		
		op.runCompleteProcedure();
	}

	
	
	private void runCompleteProcedure() throws Exception {
		connectCard();			
		SecurityInfos cardAccess = getEFCardAccess();	
		PublicKey ephPacePublicKey = performPACE(cardAccess);
		
		KeyPair ephPCDKeyPair = performTerminalAuthentication(cardAccess, ephPacePublicKey);
		

		
		//Lese EF.CardSecurity
		byte[] efcsBytes = facs.getFile(FID_EFCardSec, true);
		logger.info("EF.CardSecurity read");
		
		
		//Extrahiere SecurityInfos
		SecurityInfos efcs = decodeEFCardSecurity(efcsBytes);
		FileSystem.saveFile("/home/tsenger/Desktop/EF.CardSecurity_eAT.bin", efcsBytes);
		logger.debug("EF.CardSecurity \n: " + efcs);
		logger.info("EF.CardSecurity decoded");

		
		// Erzeuge Chip Authentication SandOp und übergebe CardHandler
		CAOperator cop = new CAOperator(ch);
		
		
		//Initialisiere und führe id_CA durch
		cop.initialize(efcs.getChipAuthenticationInfoList().get(0), efcs.getChipAuthenticationPublicKeyInfoList().get(0), ephPCDKeyPair);
		SecureMessaging sm2 = cop.performCA();
		
		// Wenn id_CA erfolgreich war, wird ein neues SecureMessaging Object zurückgeliefert welches die neuen Schlüssel enthält
		if (sm2 != null) {
			logger.info("id_CA established!");
			ch.setSecureMessaging(sm2);
		} else {
			logger.warn("Couldn't establish id_CA");
		}
		
		//Selektiere die eID-Anwendung
		ch.transceive(CardCommands.selectApp(Hex.decode("E80704007F00070302")));
		
		// Lese eine Datengrupppe
		byte dgno = 4;
		byte[] dgdata= facs.getFile(dgno);
		DERApplicationSpecific derapp = (DERApplicationSpecific) DERApplicationSpecific.fromByteArray(dgdata);
		DERUTF8String name = (DERUTF8String) derapp.getObject();
		logger.info("Content of DG0"+dgno+": "+ name);

	}
	
	
	private void connectCard() {
		
		//CardHandler erzeugen und erstes Terminal verbinden
		ch = new AmCardHandler();
		
		try {
			if (!ch.connect(slotID))  // 0 = First terminal
			{
				logger.error("Can't connect to card!");
				System.exit(0);
			}
		} catch (CardException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		facs = new FileAccess(ch);

	}
	
	
	private SecurityInfos getEFCardAccess() throws CardException {
		
		SecurityInfos efca = null;
		try {
			byte[] efcaBytes = facs.getFile(FID_EFCardAccess, true);
			efca = new SecurityInfos();
			efca.decode(efcaBytes);
			logger.info("EF.CardAccess bytes:\n"+HexString.bufferToHex(efcaBytes));
			logger.info("EF.CardAccess decoded");
			logger.debug("\n"+efca);
		} catch (IOException e) {
			logger.error("Couldn't decode EF.CardAccess",e);
		} catch (SecureMessagingException e) {
			logger.error("SecureMessaging failed!", e);
		}
		return efca;
	}
	
	private PublicKey performPACE(SecurityInfos cardAccess) throws PaceException, CardException {
		
		//Initialisiere id_PACE mit dem ersten id_PACE-Info aus dem EF.CardAccess
		PaceOperator pop = new PaceOperator(ch);
	
		if (cardAccess.getPaceDomainParameterInfoList().size()>0) //Properitäre id_PACE Domain-Paramter vorhanden
			pop.setAuthTemplate(cardAccess.getPaceInfoList().get(0), cardAccess.getPaceDomainParameterInfoList().get(0), can, 2, 2);
		else pop.setAuthTemplate(cardAccess.getPaceInfoList().get(0), can , 2, 2); //Standardisierte id_PACE Domain Paramter
				
		//Führe id_PACE durch
		SecureMessaging sm = null;
		try {
			sm = pop.performPace();
		} catch (SecureMessagingException e) {
			throw new PaceException("SecureMessaging failure while performing id_PACE",e);
		}
				
		//Wenn id_PACE erfolgreich durchgeführt wurde, wird sein SecureMessaging-Objekt
		//mit gültigen Session-Keys zurückgeliefert.
		if (sm!=null) logger.info("id_PACE established");
		ch.setSecureMessaging(sm);			
		return pop.getPKpicc();
	}
	
	private KeyPair performTerminalAuthentication(SecurityInfos cardAccess, PublicKey ephPacePublicKey) throws TAException, SecureMessagingException, CardException {
		if (ephPacePublicKey==null) {
			logger.error("id_PACE didn't provide an ephemeral Public Key for Terminal Terminal Authentication.");
		}
		
		//Erzeuge neuen Terminal Authentication SandOp und übergebe den CardHandler
		TAOperator top = new TAOperator(ch);

		//id_TA benötigt zur Berechnung des ephemeralen PCD public Key die DomainParameter für die id_CA
		DomainParameter dp = new DomainParameter(cardAccess.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter());


		//Zertifikate für TA festlegen
		
		String cvcaCertFile = "certs/PersoSim_HJP/DETESTeID00004.cvcert";
		String dvCertFile = "certs/PersoSim_HJP/DETESTeID00004_DEDVTIDHJP00001.cvcert";
		String terminalCertFile = "certs/PersoSim_HJP/DEDVTIDHJP00001_DEATTIDBSI00001.cvcert";
		String privateKeyFile = "certs/PersoSim_HJP/DEDVTIDHJP00001_DEATTIDBSI00001.pkcs8";

		CertificateProvider cp = null;
		try {
			cp = new CertificateProvider(cvcaCertFile, dvCertFile, terminalCertFile, privateKeyFile);
		} catch (IOException e) {
			logger.error("Can't load one or more certification file(s).",e);
		}
		
		// TA ausführen, Rückgabe ist der ephemerale PCD Public Key
		KeyPair ephPCDKeyPair = null;
		try {
			top.initialize(cp, dp, ephPacePublicKey);
			ephPCDKeyPair = top.performTA();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		logger.info("TA established");
		
		return ephPCDKeyPair;		
	}
	
	private static SecurityInfos decodeEFCardSecurity(byte[] data) throws IOException, CertificateException, NoSuchProviderException, CMSException, OperatorCreationException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		ASN1Sequence asnSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
		ContentInfo contentInfo = ContentInfo.getInstance(asnSeq);
		DERSequence derSeq = (DERSequence) contentInfo.getContent();
		
		System.out.println("ContentType: "+ contentInfo.getContentType().toString());
		SignedData cardSecurity = SignedData.getInstance(derSeq);		
		
		//Get SecurityInfos
		ContentInfo encapContentInfo = cardSecurity.getEncapContentInfo();
		DEROctetString octString = (DEROctetString) encapContentInfo.getContent();
		SecurityInfos si = new SecurityInfos();
		si.decode(octString.getOctets());
	
		return si;
	}
	
}
