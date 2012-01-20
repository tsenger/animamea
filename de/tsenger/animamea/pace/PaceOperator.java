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
import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp1024_160;
import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp2048_224;
import static de.tsenger.animamea.pace.DHStandardizedDomainParameters.modp2048_256;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.math.ec.ECCurve.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.KeyDerivationFunction;
import de.tsenger.animamea.asn1.AmDHPublicKey;
import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.DynamicAuthenticationData;
import de.tsenger.animamea.asn1.PaceDomainParameterInfo;
import de.tsenger.animamea.asn1.PaceInfo;
import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.crypto.AmCryptoProvider;
import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.tools.Converter;
import de.tsenger.animamea.tools.HexString;

/**
 * PaceOperator stellt Methoden zur Durchführung des PACE-Protokolls zur Verfügung
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */

public class PaceOperator {

	private Pace pace = null;
	private AmCryptoProvider crypto = null;
	private DHParameters dhParameters = null;
	private X9ECParameters ecdhParameters = null;
	private AmCardHandler cardHandler = null;
	private int passwordRef = 0;
	private byte[] passwordBytes = null;
	private String protocolOIDString = null;
	private int keyLength = 0;
	private int terminalType = 0;
	private byte[] pk_picc = null;

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
	 * @param pi PACEInfo enthält die Crypto-Information zur Durchführung von PACE
	 * @param password Das Password welches für PACE verwendet werden soll
	 * @param pwRef Typ des Passwort (1=MRZ, 2=CAN, 3=PIN, 4=PUK)
	 * @param terminalRef Rolle des Terminals laut BSI TR-03110 (1=IS, 2=AT, 3=ST)
	 */
	public void setAuthTemplate(PaceInfo pi, String password, int pwRef,
			int terminalRef) {

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (passwordRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getStandardizedDomainParameters(pi.getParameterId());

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}

	/**
	 * Initialisiert PACE mit properitären Domain Parametern.
	 * 
	 * @param pi PACEInfo enthält alle Crypto-Information zur Durchführung von PACE
	 * @param pdpi Enthält die properitären Domain Parameter für PACE
	 * @param password Das Password welches für PACE verwendet werden soll
	 * @param pwRef Typ des Passwort (1=MRZ, 2=CAN, 3=PIN, 4=PUK)
	 * @param terminalRef Rolle des Terminals laut BSI TR-03110 (1=IS, 2=AT, 3=ST)
	 */
	public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi,
			String password, int pwRef, int terminalRef) throws Exception {

		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
		terminalType = terminalRef;

		if (pi.getParameterId() >= 0 && pi.getParameterId() <= 31)
			throw new Exception(
					"ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new Exception(
					"PaceInfo doesn't match the PaceDomainParameterInfo");

		if (pwRef == 1)
			passwordBytes = calcSHA1(password.getBytes());
		else
			passwordBytes = password.getBytes();

		getProprietaryDomainParameters(pdpi);

		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_DH_IM.toString()))
			pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())
				|| protocolOIDString.startsWith(id_PACE_ECDH_IM.toString()))
			pace = new PaceECDH(ecdhParameters);

		getCryptoInformation(pi);
	}


	/**
	 * Führt alle Schritte des PACE-Protokolls durch und liefert bei Erfolg 
	 * eine mit den ausgehandelten Schlüsseln intialisierte SecureMessaging-Instanz zurück.
	 * 
	 * @return Bei Erfolg von PACE wird eine mit den ausgehandelten Schlüsseln 
	 * 			intialisierte SecureMessaging-Instanz zurückgegeben. Anderfalls <code>null</code>.
	 * @throws PaceException 
	 * @throws CardException 
	 * @throws IOException 
	 * @throws SecureMessagingException 
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
	 * @throws Exception
	 */
	public SecureMessaging performPace() throws PaceException, CardException, IOException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, SecureMessagingException {

		// send MSE:SetAT
		int resp = sendMSESetAT(terminalType).getSW();
		if (resp != 0x9000)
			throw new PaceException("MSE:Set AT failed. SW: " + Integer.toHexString(resp));

		// send first GA and get nonce
		byte[] nonce_z = getNonce().getEncryptedNonce80();
		byte[] nonce_s = decryptNonce(nonce_z);
		byte[] X1 = pace.getX1(nonce_s);

		// X1 zur Karte schicken und Y1 empfangen
		byte[] Y1 = mapNonce(X1).getMappingData82();

		byte[] X2 = pace.getX2(Y1);
		// X2 zur Karte schicken und Y2 empfangen.
		byte[] Y2 = performKeyAgreement(X2).getEphemeralPK84();
		
		// Y2 ist PK_Picc der für die TA benötigt wird.
		pk_picc = Y2.clone();

		byte[] S = pace.getSharedSecret_K(Y2);
		byte[] kenc = getKenc(S);
		byte[] kmac = getKmac(S);

		// Authentication Token T_PCD berechnen
		byte[] tpcd = calcAuthToken(Y2, kmac);

		// Authentication Token T_PCD zur Karte schicken und Authentication Token T_PICC empfangen
		byte[] tpicc = performMutualAuthentication(tpcd).getAuthToken86();

		// Authentication Token T_PICC' berechnen
		byte[] tpicc_strich = calcAuthToken(X2, kmac);

		// Prüfe ob T_PICC = T_PICC'
		if (!Arrays.areEqual(tpicc, tpicc_strich)) throw new PaceException("Authentication Tokens are different");
		
		return new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
	}
	
	/**
	 * Liefert den ephemeralen Public Key des Chips zurück. Dieser wird für Terminal
	 * Authentisierung nach V.2 benötigt.
	 * @return
	 */
	public byte[] getPKpicc() {
		return pk_picc;
	}
	
	/**
	 * Der Authentication Token berechnet sich aus dem MAC (mit Schlüssel kmac) über 
	 * einen PublicKey welcher den Object Identifier des verwendeten Protokolls und den 
	 * von der empfangenen ephemeralen Public Key (Y2) enthält. 
	 * Siehe dazu TR-03110 V2.05 Kapitel A.2.4 und D.3.4
	 * Hinweis: In älteren Versionen des PACE-Protokolls wurden weitere Parameter zur 
	 * Berechnung des Authentication Token herangezogen.
	 * 
	 * @param Y2 Byte-Array welches ein DO84 (Ephemeral Public Key) enthält
	 * @param kmac Schlüssel K_mac für die Berechnung des MAC
	 * @return Authentication Token
	 */
	private byte[] calcAuthToken(byte[] Y2, byte[] kmac) {
		byte[] tpcd = null;
		if (pace instanceof PaceECDH) {
			Fp curve = (Fp) ecdhParameters.getCurve();
			ECPoint pointY = Converter.byteArrayToECPoint(Y2, curve);
			AmECPublicKey pkpcd = new AmECPublicKey(protocolOIDString, pointY);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		else if (pace instanceof PaceDH) {
			BigInteger y = new BigInteger(Y2);
			AmDHPublicKey pkpcd = new AmDHPublicKey(protocolOIDString, y);
			tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		}
		return tpcd;
	}

	private DynamicAuthenticationData performMutualAuthentication(byte[] authToken) throws PaceException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, IOException, SecureMessagingException {

		DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
		dad85.setAuthenticationToken85(authToken);
		byte[] dadBytes = dad85.getDEREncoded();

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(Hex.decode("00860000"));
		bos.write(dadBytes.length);
		bos.write(dadBytes);
		bos.write(0);

		CommandAPDU capdu = new CommandAPDU(bos.toByteArray());
		ResponseAPDU resp = cardHandler.transceive(capdu);
		if (resp.getSW() != 36864)
			throw new PaceException("perform Key Agreement returns: "
					+ HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}

	/**
	 * @return
	 * @throws IOException 
	 * @throws SecureMessagingException 
	 * @throws CardException 
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
	 * @throws Exception
	 */
	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK) throws PaceException, IOException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, SecureMessagingException {

		DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
		dad83.setEphemeralPK83(ephemeralPK);
		byte[] dadBytes = dad83.getDEREncoded();

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(Hex.decode("10860000"));
		bos.write(dadBytes.length);
		bos.write(dadBytes);
		bos.write(0);

		CommandAPDU capdu = new CommandAPDU(bos.toByteArray());
		ResponseAPDU resp = cardHandler.transceive(capdu);
		if (resp.getSW() != 36864)
			throw new PaceException("perform Key Agreement returns: " + HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}

	/**
	 * @return
	 * @throws IOException 
	 * @throws SecureMessagingException 
	 * @throws CardException 
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
	 * @throws Exception
	 */
	private DynamicAuthenticationData mapNonce(byte[] mappingData) throws PaceException, IOException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, SecureMessagingException {

		DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
		dad81.setMappingData81(mappingData);
		byte[] dadBytes = dad81.getDEREncoded();

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		bos.write(Hex.decode("10860000"));
		bos.write(dadBytes.length);
		bos.write(dadBytes);
		bos.write(0);

		CommandAPDU capdu = new CommandAPDU(bos.toByteArray());
		ResponseAPDU resp = cardHandler.transceive(capdu);
		if (resp.getSW() != 36864)
			throw new PaceException("Map nonce returns: " + HexString.bufferToHex(resp.getBytes()));

		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}

	private ResponseAPDU sendMSESetAT(int terminalType) throws PaceException, CardException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, IOException, SecureMessagingException {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_PACE);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(passwordRef);
		switch (terminalType) {
		case 0:
			break;
		case 1:
			mse.setISChat();
			break;
		case 2:
			mse.setATChat();
			break;
		case 3:
			mse.setSTChat();
			break;
		default:
			throw new PaceException("Unknown Terminal Reference: " + terminalType);
		}
		return cardHandler.transceive(new CommandAPDU(mse.getBytes()));
	}

	/**
	 * Send a plain General Authentication Command to get a encrypted nonce from
	 * the card.
	 * 
	 * @return
	 * @throws SecureMessagingException 
	 * @throws IOException 
	 * @throws CardException 
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
	 * @throws Exception
	 */
	private DynamicAuthenticationData getNonce() throws PaceException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, IOException, SecureMessagingException {
		CommandAPDU capdu = new CommandAPDU(Hex.decode("10860000027C0000"));
		ResponseAPDU resp = cardHandler.transceive(capdu);
		if (resp.getSW() != 36864)
			throw new PaceException("Get nonce returns: " + HexString.bufferToHex(resp.getBytes()));
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}

	private byte[] decryptNonce(byte[] z) {

		byte[] derivatedPassword = null;
		try {
			derivatedPassword = getKey(keyLength, passwordBytes, 3);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return crypto.decryptBlock(derivatedPassword, z);
	}

	private byte[] getKenc(byte[] sharedSecret_S) {
		try {
			return getKey(keyLength, sharedSecret_S, 1);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private byte[] getKmac(byte[] sharedSecret_S) {
		try {
			return getKey(keyLength, sharedSecret_S, 2);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	private byte[] getKey(int keyLength, byte[] K, int c) throws Exception {

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

	// TODO Funktioniert momentan nur mit EC
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi)
			throws Exception {
		if (pdpi.getDomainParameter().getAlgorithm().toString()
				.contains(BSIObjectIdentifiers.id_ecc.toString())) {
			ASN1Sequence seq = (ASN1Sequence) pdpi.getDomainParameter()
					.getParameters().getDERObject().toASN1Object();
			ecdhParameters = new X9ECParameters(seq);
		} else
			throw new Exception(
					"Can't decode properietary domain parameters in PaceDomainParameterInfo!");
	}

	private void getStandardizedDomainParameters(int parameterId) {

		switch (parameterId) {
		case 0:
			dhParameters = modp1024_160();
			break;
		case 1:
			dhParameters = modp2048_224();
			break;
		case 3:
			dhParameters = modp2048_256();
			break;
		case 8:
			ecdhParameters = SECNamedCurves.getByName("secp192r1");
			break;
		case 9:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp192r1");
			break;
		case 10:
			ecdhParameters = SECNamedCurves.getByName("secp224r1");
			break;
		case 11:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp224r1");
			break;
		case 12:
			ecdhParameters = SECNamedCurves.getByName("secp256r1");
			break;
		case 13:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
			break;
		case 14:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp320r1");
			break;
		case 15:
			ecdhParameters = SECNamedCurves.getByName("secp384r1");
			break;
		case 16:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp384r1");
			break;
		case 17:
			ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp512r1");
			break;
		case 18:
			ecdhParameters = SECNamedCurves.getByName("secp521r1");
			break;
		}
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
		} catch (NoSuchAlgorithmException ex) {
		}

		md.update(input);
		return md.digest();
	}

	/**
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge
	 * für PACE
	 */
	private void getCryptoInformation(PaceInfo pi) {
		String protocolOIDString = pi.getProtocolOID();
		if (protocolOIDString.equals(id_PACE_DH_GM_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_3DES_CBC_CBC
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_3DES_CBC_CBC
						.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_128
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_128
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128
						.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192
						.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256
				.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256
						.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256
						.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

}
