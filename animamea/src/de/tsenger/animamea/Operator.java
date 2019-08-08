/**
 *  Copyright 2011-2017, Tobias Senger
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
import java.security.PublicKey;
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
import de.tsenger.animamea.tools.HexString;

/**
 * 
 * @author Tobias Senger <tobias@t-senger.de>
 */
public class Operator {
	
	//MODIFY this value to your actual Password (eg. PIN, CAN, etc) see also pwRef
	private final String password = "300841";
	
	//MODIFY Password Reference to set which PW shall be used for PACE (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	private final int pwRef = 2;
	
	//MODIFY role of the terminal shall be used for PACE (1=id_IS, 2=id_AT, 3=id_ST, 0=unauthenticated terminal)
	private final int terminalRef = 2;
		
	//MODIFY this value to the slotID where your card (or simulator) is insert
	private final int slotID = 0;

	/* 
	 * MODIFY this paths to your certificates and private key for TA
	 * If you use the PersoSim simulator (www.persosim.de) you can just use these certificates 
	 * to successful perform TA. 
	 */ 
	String cvcaCertFile = "certs/PersoSim/DETESTeID00004.cvcert";
	String dvCertFile = "certs/PersoSim/DETESTeID00004_DEDVTIDHJP00001.cvcert";
	String terminalCertFile = "certs/PersoSim/DEDVTIDHJP00001_DEATTIDBSI00001.cvcert";
	String privateKeyFile = "certs/PersoSim/DEDVTIDHJP00001_DEATTIDBSI00001.pkcs8";
	
	

	static final byte[] FID_EFCardAccess = new byte[] { (byte) 0x01, (byte) 0x1C };
	static final byte[] FID_DIR = new byte[] { (byte) 0x2F, (byte) 0x00 };
	static final byte[] FID_ATR = new byte[] { (byte) 0x2F, (byte) 0x01 };
	static final byte[] FID_EFCardSec = new byte[] { (byte) 0x01, (byte) 0x1D };
	static final byte[] FID_EFChipSec = new byte[] { (byte) 0x01, (byte) 0x1B };
	static final byte SFID_EFCA = (byte) 0x1C;

	static final byte[] FID_SOD = new byte[] { (byte) 0x01, (byte) 0x1D };
	static final byte[] FID_DG1 = new byte[] { (byte) 0x01, (byte) 0x01 };
	
    static final byte[] EID_APP_ID = new byte[] {(byte)0xE8, 0x07, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x02}; 

	static Logger logger = Logger.getLogger(Operator.class);

	private AmCardHandler ch = null;
	private FileAccess facs = null;
	
	

	public static void main(String[] args) throws Exception {

		PropertyConfigurator.configure("log4j.properties");

		logger.info("Entering application.");

		Operator op = new Operator();
		if (op.connectCard()) {
			op.runCompleteProcedure();
		}
	}

	private void runCompleteProcedure() throws Exception {

		SecurityInfos cardAccess = getEFCardAccess();
		PublicKey ephPacePublicKey = performPACE(cardAccess);

		KeyPair ephPCDKeyPair = performTerminalAuthentication(cardAccess, ephPacePublicKey);

		// read EF.CardSecurity
		byte[] efcsBytes = facs.getFile(FID_EFCardSec, true);
		logger.info("EF.CardSecurity read");

		// extract SecurityInfos
		SecurityInfos efcs = decodeEFCardSecurity(efcsBytes);
		
		logger.debug("EF.CardSecurity \n: " + efcs);
		logger.info("EF.CardSecurity decoded");

		// create a Chip Authentication Operator and hand over the CardHandler
		CAOperator cop = new CAOperator(ch);

		// Initialize and perform CA 
		cop.initialize(efcs.getChipAuthenticationInfoList().get(0), efcs.getChipAuthenticationPublicKeyInfoList().get(0), ephPCDKeyPair);
		SecureMessaging sm2 = cop.performCA();

		// If CA was successful a new SecureMessaging object will be returned which 
		// will we used for SecureMessaging from now on 
		if (sm2 != null) {
			logger.info("id_CA established!");
			ch.setSecureMessaging(sm2);
		} else {
			logger.warn("Couldn't establish id_CA");
		}

		// select the eID application
		ch.transceive(CardCommands.selectApp(EID_APP_ID));

		// read a datagroup (e.g. DG4 contains the first name)
		byte dgno = 4;
		byte[] dgdata = facs.getFile(dgno);
		DERApplicationSpecific derapp = (DERApplicationSpecific) DERApplicationSpecific.fromByteArray(dgdata);
		DERUTF8String name = (DERUTF8String) derapp.getObject();
		logger.info("Content of DG0" + dgno + ": " + name);

	}

	private boolean connectCard() {

		// create an animamea CardHandler and connect the Terminal
		ch = new AmCardHandler();

		try {
			if (!ch.connect(slotID)) {
				logger.error("Can't connect to card!");
				return false;
			}
		} catch (CardException e1) {
			logger.error(e1.getLocalizedMessage());
		}

		facs = new FileAccess(ch);
		return true;

	}

	private SecurityInfos getEFCardAccess() throws CardException {

		SecurityInfos efca = null;
		try {
			byte[] efcaBytes = facs.getFile(FID_EFCardAccess, true);
			efca = new SecurityInfos();
			efca.decode(efcaBytes);
			logger.info("EF.CardAccess bytes:\n"+ HexString.bufferToHex(efcaBytes));
			logger.info("EF.CardAccess decoded");
			logger.debug("\n" + efca);
		} catch (IOException e) {
			logger.error("Couldn't decode EF.CardAccess", e);
		} catch (SecureMessagingException e) {
			logger.error("SecureMessaging failed!", e);
		}
		return efca;
	}

	private PublicKey performPACE(SecurityInfos cardAccess)
			throws PaceException, CardException {

		// initialize PACE with the first PACE-Info from EF.CardAccess
		PaceOperator pop = new PaceOperator(ch);

		if (cardAccess.getPaceDomainParameterInfoList().size() > 0) 
			// explicit PACE domain parameter available
			pop.setAuthTemplate(cardAccess.getPaceInfoList().get(0), cardAccess.getPaceDomainParameterInfoList().get(0), password, pwRef, terminalRef);
		else
			// standardized PACE domain parameter
			pop.setAuthTemplate(cardAccess.getPaceInfoList().get(0), password, pwRef, terminalRef); 

		// perform PACE
		SecureMessaging sm = null;
		try {
			sm = pop.performPace();
		} catch (SecureMessagingException e) {
			throw new PaceException("SecureMessaging failure while performing PACE", e);
		}

		// If PACE was successful a new SecureMessaging object will be returned which 
		// will we used for SecureMessaging
		if (sm != null)
			logger.info("___PACE established!___");
		ch.setSecureMessaging(sm);
		return pop.getPKpicc();
	}

	private KeyPair performTerminalAuthentication(SecurityInfos cardAccess,
			PublicKey ephPacePublicKey) throws TAException,
			SecureMessagingException, CardException {
		if (ephPacePublicKey == null) {
			logger.error("PACE didn't provide an ephemeral Public Key for Terminal Terminal Authentication.");
		}

		// create a new  Terminal Authentication operator pass over the CardHandler
		TAOperator top = new TAOperator(ch);

		// To calculaten the ephemeral PCD public Key TA needs the CA domain parameter
		DomainParameter dp = new DomainParameter(cardAccess.getChipAuthenticationDomainParameterInfoList().get(0).getDomainParameter());

		CertificateProvider cp = null;
		try {
			cp = new CertificateProvider(cvcaCertFile, dvCertFile, terminalCertFile, privateKeyFile);
		} catch (IOException e) {
			logger.error("Can't load one or more certification file(s).", e);
		}

		// perform TA, ephemeral PCD Public Key will be returned after success
		KeyPair ephPCDKeyPair = null;
		try {
			top.initialize(cp, dp, ephPacePublicKey);
			ephPCDKeyPair = top.performTA();
		} catch (IllegalArgumentException | IOException e) {
			logger.error(e.getLocalizedMessage());
		}

		logger.info("TA established");

		return ephPCDKeyPair;
	}

	private SecurityInfos decodeEFCardSecurity(byte[] data)
			throws IOException, CertificateException, CMSException, OperatorCreationException {
		
		ASN1Sequence asnSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(data);
		ContentInfo contentInfo = ContentInfo.getInstance(asnSeq);
		DERSequence derSeq = (DERSequence) contentInfo.getContent();

		SignedData cardSecurity = SignedData.getInstance(derSeq);

		// Get SecurityInfos
		ContentInfo encapContentInfo = cardSecurity.getEncapContentInfo();
		DEROctetString octString = (DEROctetString) encapContentInfo.getContent();
		SecurityInfos si = new SecurityInfos();
		si.decode(octString.getOctets());

		return si;
	}

}
