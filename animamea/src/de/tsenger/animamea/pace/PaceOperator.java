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

package de.tsenger.animamea.pace;

import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_3DES_CBC_CBC;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_128;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_192;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_256;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_CAM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_CAM_AES_CBC_CMAC_128;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_CAM_AES_CBC_CMAC_192;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_CAM_AES_CBC_CMAC_256;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_3DES_CBC_CBC;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_128;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_192;
import static de.tsenger.animamea.asn1.BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_256;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.spec.DHPublicKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.AmDHPublicKey;
import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.CertificateHolderAuthorizationTemplate;
import de.tsenger.animamea.asn1.DiscretionaryData;
import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.asn1.DynamicAuthenticationData;
import de.tsenger.animamea.asn1.PaceDomainParameterInfo;
import de.tsenger.animamea.asn1.PaceInfo;
import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.crypto.AmCryptoException;
import de.tsenger.animamea.crypto.AmCryptoProvider;
import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.crypto.KeyDerivationFunction;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.tools.Converter;
import de.tsenger.animamea.tools.HexString;

/**
 * PaceOperator stellt Methoden zur Durchführung des id_PACE-Protokolls zur Verfügung
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */

public class PaceOperator {

	private Pace pace = null;
	private AmCryptoProvider crypto = null;
	private AmCardHandler cardHandler = null;
	private int passwordRef = 0;
	private byte[] passwordBytes = null;
	private String protocolOIDString = null;
	private int keyLength = 0;
	private int terminalType = 0;
	private byte[] pk_picc = null;
	private DomainParameter dp = null;
	private byte[] kenc, kmac = null;
	
	private String car, car2 = null;
	private byte[] encCAdata = null;
	private byte[] pk_mapic = null;
	
	public static final byte[] defaultChatBytes_IS = new byte[] { (byte) 0x23};
	public static final byte[] defaultChatBytes_AT = new byte[] { (byte) 0x3F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xF7 };
	public static final byte[] defaultChatBytes_ST = new byte[] { (byte) 0x03};
	
	static Logger logger = Logger.getLogger(PaceOperator.class);

	/** 
	 * Konstruktor
	 * @param ch AmCardHandler-Instanz über welches die Kartenkommandos gesendet werden.
	 */
	public PaceOperator(AmCardHandler ch) {
		cardHandler = ch;
	}

	/**
	 * Initialisiert PACE mit standardisierten Domain Parametern.
	 * 
	 * @param pi PACEInfo enthält die Crypto-Information zur Durchführung von id_PACE
	 * @param password Das Password welches für PACE verwendet werden soll
	 * @param pwRef Typ des Passwort (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	 * @param terminalRef Rolle des Terminals laut BSI TR-03110 (1=id_IS, 2=id_AT, 3=id_ST, 0=unauthenticated terminal)
	 */
	public void setAuthTemplate(PaceInfo pi, String password, int pwRef, int terminalRef) {

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (passwordRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();
		
		logger.info("K from password "+password+" is: "+HexString.bufferToHex(passwordBytes));

		dp = new DomainParameter(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dp.getDHParameter());
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_CAM.toString()))
			pace = new PaceECDH(dp.getECParameter());

		getCryptoInformation(pi);
	}

	/**
	 * Initialisiert PACE mit properitären Domain Parametern.
	 * 
	 * @param pi PACEInfo enthält alle Crypto-Information zur Durchführung von id_PACE
	 * @param pdpi Enthält die properitären Domain Parameter für id_PACE
	 * @param password Das Password welches für PACE verwendet werden soll
	 * @param pwRef Typ des Passwort (1=MRZ, 2=CAN, 3=PIN, 4=PUK). MRZ must encoded as: (SerialNumber||Date of Birth+Checksum||Date of Expiry+Checksum)
	 * @param terminalRef Rolle des Terminals laut BSI TR-03110 (1=id_IS, 2=id_AT, 3=id_ST)
	 * @throws PaceException 
	 */
	public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi, String password, int pwRef, int terminalRef) throws PaceException{

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (pi.getParameterId() >= 0 && pi.getParameterId() <= 31)
			throw new IllegalArgumentException("ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new IllegalArgumentException("PaceInfo doesn't match the PaceDomainParameterInfo");

		if (pwRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getProprietaryDomainParameters(pdpi);

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dp.getDHParameter());
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(dp.getECParameter());

		getCryptoInformation(pi);
	}
	
	
	/**
	 * Führt alle Schritte des id_PACE-Protokolls durch und liefert bei Erfolg 
	 * eine mit den ausgehandelten Schlüsseln intialisierte SecureMessaging-Instanz zurück.
	 * Verwendet einen Standard-CHAT des jeweiligen Terminaltypes. Soll PACE ohne CHAT ausgeführt werden
	 * muss <code>perfomPace(null)</code> verwendet werden.
	 * 
	 * 			Wird <code>null</code> übergeben wird PACE ohne CHAT im MSE:Set id_AT durchgeführt. 
	 * @return Bei Erfolg von PACE wird eine mit den ausgehandelten Schlüsseln 
	 * 			intialisierte SecureMessaging-Instanz zurückgegeben. Anderfalls <code>null</code>.
	 * @throws PaceException 
	 * @throws CardException 
	 * @throws SecureMessagingException 
	 */
	public SecureMessaging performPace() throws PaceException, SecureMessagingException, CardException {
		switch(terminalType) {
		case 1:
			return performPace(defaultChatBytes_IS);
		case 2:
			return performPace(defaultChatBytes_AT);
		case 3:
			return performPace(defaultChatBytes_ST);
		default:
			return performPace(null);
		}
	}

	/**
	 * Führt alle Schritte des id_PACE-Protokolls durch und liefert bei Erfolg 
	 * eine mit den ausgehandelten Schlüsseln intialisierte SecureMessaging-Instanz zurück.
	 * 
	 * @param optCHAT optional kann ein CHAT angegeben werden. Muss zum Terminaltype passen.
	 * 			CHAT mit nur einem Byte müssen als Byte-Array der Länge 1 übergeben werden.
	 * 			Wird <code>null</code> übergeben wird PACE ohne CHAT im MSE:Set id_AT durchgeführt. 
	 * @return Bei Erfolg von PACE wird eine mit den ausgehandelten Schlüsseln 
	 * 			intialisierte SecureMessaging-Instanz zurückgegeben. Anderfalls <code>null</code>.
	 * @throws PaceException 
	 * @throws CardException 
	 * @throws SecureMessagingException 
	 */

	public SecureMessaging performPace(byte[] optCHAT) throws PaceException, SecureMessagingException, CardException {

		// send MSE:SetAT
		int resp = sendMSESetAT(terminalType, optCHAT).getSW();
		if (resp != 0x9000)	throw new PaceException("MSE:Set id_AT failed. SW: " + Integer.toHexString(resp));

		// send first GA and get nonce
		byte[] nonce_z = getNonce().getDataObject(0);

		logger.debug("encrypted nonce z: "+HexString.bufferToHex(nonce_z));
		byte[] nonce_s = decryptNonce(nonce_z);
		logger.debug("decrypted nonce s: "+HexString.bufferToHex(nonce_s));
		byte[] X1 = pace.getX1(nonce_s);

		// X1 zur Karte schicken und Y1 empfangen
		byte[] Y1 = mapNonce(X1).getDataObject(2);
		
		//Y1 ist PK_MapIc für id_PACE-CAM
		pk_mapic  = Y1.clone();

		byte[] X2 = pace.getX2(Y1);
		// X2 zur Karte schicken und Y2 empfangen.
		byte[] Y2 = performKeyAgreement(X2).getDataObject(4);
		
		// Y2 ist PK_Picc der für die id_TA benötigt wird.
		pk_picc = Y2.clone();

		byte[] S = pace.getSharedSecret_K(Y2);
		kenc = getKenc(S);
		kmac = getKmac(S);
		logger.debug("shared secret (K bzw S): "+HexString.bufferToHex(S));
		logger.debug("Kenc: "+HexString.bufferToHex(kenc));
		logger.debug("Kmac: "+HexString.bufferToHex(kmac));
		// Authentication Token T_PCD berechnen
		byte[] tpcd = calcAuthToken(kmac, Y2);

		// Authentication Token T_PCD zur Karte schicken und Authentication Token T_PICC empfangen
		DynamicAuthenticationData dad = performMutualAuthentication(tpcd);
		byte[] tpicc = dad.getDataObject(6);
		if (dad.getDataObject(7)!= null) {
			car = new String(dad.getDataObject(7));
			logger.info("CAR: "+car);
		}
		if (dad.getDataObject(8)!= null) {
			car2 = new String(dad.getDataObject(8));
			logger.info("CAR2: "+ car2);
		}
		if (dad.getDataObject(0x0A)!= null) {
			encCAdata = dad.getDataObject(0x0A);
			logger.info("Encrypted id_CA Data: "+HexString.bufferToHex(encCAdata));
			
		}

		// Authentication Token T_PICC' berechnen
		byte[] tpicc_strich = calcAuthToken(kmac, X2);
		logger.debug("tpicc': "+HexString.bufferToHex(tpicc_strich));

		// Prüfe ob T_PICC = T_PICC'
		if (!Arrays.areEqual(tpicc, tpicc_strich)) throw new PaceException("Authentication Tokens are different");
		
		return new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
	}
	


	/**
	 * Liefert den ephemeralen Public Key des Chips zurück. Dieser wird für Terminal
	 * Authentisierung nach V.2 benötigt.
	 * @return
	 */
	public PublicKey getPKpicc() {
		
		KeyFactory fact = null;
		PublicKey pubKey = null;
		KeySpec pubKeySpec = null;
		
		if (dp.getDPType().equals("ECDH")) {
			ECPoint q = Converter.byteArrayToECPoint(pk_picc, (Fp) dp.getECParameter().getCurve()).normalize();
			pubKeySpec = new ECPublicKeySpec(q, dp.getECParameter());	
			
		} else if (dp.getDPType().equals("DH")) {
			BigInteger y = new BigInteger(1, pk_picc);
			pubKeySpec = new DHPublicKeySpec(y, dp.getDHParameter().getP(), dp.getDHParameter().getG());
		}
		
		try {
			fact = KeyFactory.getInstance(dp.getDPType(), "BC");
			pubKey = fact.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		} catch (NoSuchProviderException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		} catch (InvalidKeySpecException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		}
		
		return pubKey;
	}
	
	/** Liefert die nach PACE vom Chip zurückgelieferte Certificate Authority Reference
	 *  für die Terminal Authentisierung zurück. 
	 * @return aktuelle Certificate Authority Reference
	 */
	public String getCAR() {
		return car;
	}
	
	/** Liefert die nach PACE vom Chip zurückgelieferte alternative Certificate Authority Reference
	 *  für die Terminal Authentisierung zurück. 
	 * @return alternative Certificate Authority Reference
	 */
	public String getCAR2() {
		return car2;
	}
	
	/** Liefert die nach id_PACE-CAM vom Chip zurückgelieferte und entschlüsselte Chip Authentication Data zurück. 
	 * @return  Decrypted Chip Authentication Data
	 */
	
	public byte[] getCAData() {
		byte[] iv = new byte[16];
		for (int i=0;i<16;i++) iv[i] = (byte)0xFF;
		logger.info("IV: "+HexString.bufferToHex(iv));
		logger.info("Kenc: "+HexString.bufferToHex(kenc));
		crypto.init(kenc, iv);
		try {
			return crypto.decrypt(encCAdata);
		} catch (AmCryptoException e) {
			logger.error(e.getLocalizedMessage());
		}
		return null;
	}
	
	public PublicKey getPKmapic() {
		
		KeyFactory fact = null;
		PublicKey pubKey = null;
		
		ECPoint q = Converter.byteArrayToECPoint(pk_mapic, (Fp) dp.getECParameter().getCurve()).normalize();
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(q, dp.getECParameter());
		try {
			fact = KeyFactory.getInstance(dp.getDPType(), "BC");
			pubKey = fact.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		} catch (NoSuchProviderException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		} catch (InvalidKeySpecException e) {
			logger.warn("Couldn't generate ephemeral public key.", e);
		}
		
		return pubKey;
	}


	/**
	 * Der Authentication Token berechnet sich aus dem MAC (mit Schlüssel kmac) über 
	 * einen AmPublicKey welcher den Object Identifier des verwendeten Protokolls und den 
	 * von der empfangenen ephemeralen Public Key (Y2) enthält. 
	 * Siehe dazu TR-03110 V2.05 Kapitel A.2.4 und D.3.4
	 * Hinweis: In älteren Versionen des id_PACE-Protokolls wurden weitere Parameter zur 
	 * Berechnung des Authentication Token herangezogen.
	 * 
	 * @param data Byte-Array welches ein DO84 (Ephemeral Public Key) enthält
	 * @param kmac Schlüssel K_mac für die Berechnung des MAC
	 * @return Authentication Token
	 */
	private byte[] calcAuthToken(byte[] kmac, byte[] data) {
		byte[] tpcd = null;
		if (pace instanceof PaceECDH) {
			Fp curve = (Fp) dp.getECParameter().getCurve();
			ECPoint pointY = Converter.byteArrayToECPoint(data, curve).normalize();
			AmECPublicKey pkpcd = new AmECPublicKey(protocolOIDString, pointY);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		else if (pace instanceof PaceDH) {
			BigInteger y = new BigInteger(1, data);
			AmDHPublicKey pkpcd = new AmDHPublicKey(protocolOIDString, y);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		return tpcd;
	}
	
	private DynamicAuthenticationData sendGeneralAuthenticate(boolean chaining, byte[] data) throws SecureMessagingException, CardException, PaceException {
		
		CommandAPDU capdu = new CommandAPDU(chaining?0x10:0x00, 0x86, 0x00, 0x00, data, 0xFF);
				
		ResponseAPDU resp = cardHandler.transceive(capdu);
		
		if (!(resp.getSW() == 0x9000 || resp.getSW() == 0x6282))
			throw new PaceException("General Authentication returns: " + HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
		return dad;
	}

	private DynamicAuthenticationData performMutualAuthentication(byte[] authToken) throws SecureMessagingException, CardException, PaceException {

		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad85.addDataObject(5, authToken);
		
		try {
			rspdad = sendGeneralAuthenticate(false, dad85.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
		
		return rspdad;
	}


	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK) throws PaceException, CardException, SecureMessagingException {

		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad83.addDataObject(3, ephemeralPK);
		
		try {
			rspdad =  sendGeneralAuthenticate(true, dad83.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
		
		return rspdad;
	}


	private DynamicAuthenticationData mapNonce(byte[] mappingData) throws SecureMessagingException, CardException, PaceException {

		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
		DynamicAuthenticationData rspdad = null;
		dad81.addDataObject(1, mappingData);

		try {
			rspdad = sendGeneralAuthenticate(true, dad81.getEncoded(ASN1Encoding.DER));
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
		
		return rspdad;
	}

	private ResponseAPDU sendMSESetAT(int terminalType, byte[] chatBytes ) throws PaceException, SecureMessagingException, CardException {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_PACE);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(passwordRef);
		DiscretionaryData disData = null;
		CertificateHolderAuthorizationTemplate chat = null;
			
		switch (terminalType) {
		case 0:
			break;
		case 1: 
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_IS, disData);
				mse.setCHAT(chat);
			}			
			break;
		case 2:
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_AT, disData);
				mse.setCHAT(chat);
			}			
			break;
		case 3:
			if (chatBytes!=null) {
				disData = new DiscretionaryData(chatBytes);
				chat = new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_ST, disData);
				mse.setCHAT(chat);
			}
			break;
		default:
			throw new PaceException("Unknown Terminal Reference: " + terminalType);
		}
		return cardHandler.transceive(mse.getCommandAPDU());
	}


	private DynamicAuthenticationData getNonce() throws PaceException, SecureMessagingException, CardException {
		
		byte[] data = new byte[]{0x7C,0x00};
		
		return sendGeneralAuthenticate(true, data);
	}

	/**
	 * @param z
	 * @return
	 */
	private byte[] decryptNonce(byte[] z) {
		byte[] derivatedPassword = getKey(keyLength, passwordBytes, 3);
		logger.debug("derivatedPassword K_pi: "+HexString.bufferToHex(derivatedPassword));
		return crypto.decryptBlock(derivatedPassword, z);
	}

	/**
	 * @param sharedSecret_S
	 * @return
	 */
	private byte[] getKenc(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 1);
	}

	/**
	 * @param sharedSecret_S
	 * @return
	 */
	private byte[] getKmac(byte[] sharedSecret_S) {
		return getKey(keyLength, sharedSecret_S, 2);
	}

	/**
	 * @param keyLength
	 * @param K
	 * @param c
	 * @return
	 */
	private byte[] getKey(int keyLength, byte[] K, int c)  {

		byte[] key = null;

		KeyDerivationFunction kdf = new KeyDerivationFunction(K, c);

		switch (keyLength) {
		case 112:
			key = kdf.getDESedeKey();
			break;
		case 128:
			key = kdf.getAES128Key();
			break;
		case 192:
			key = kdf.getAES192Key();
			break;
		case 256:
			key = kdf.getAES256Key();
			break;
		}
		return key;
	}

	
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi) throws PaceException {
		if (pdpi.getDomainParameter().getAlgorithm().toString().contains(BSIObjectIdentifiers.id_ecc.toString())) {
			dp = new DomainParameter(pdpi.getDomainParameter());
		} else
			throw new PaceException("Can't decode properietary domain parameters in PaceDomainParameterInfo!");
	}


	/**
	 * Berechnet den SHA1-Wert des übergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom ÃŒbergebenen Byte-Array
	 */
	private byte[] calcSHA1(byte[] input) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException ex) {} 

		md.update(input);
		return md.digest();
	}

	/**
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge
	 * für id_PACE
	 */
	private void getCryptoInformation(PaceInfo pi) {
		String protocolOIDString = pi.getProtocolOID();
		if (protocolOIDString.equals(id_PACE_DH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_3DES_CBC_CBC.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_128.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_192.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_CAM_AES_CBC_CMAC_256.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

}
