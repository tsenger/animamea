/**
 * 
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.KeyDerivationFunction;
import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.DynamicAuthenticationData;
import de.tsenger.animamea.asn1.PaceDomainParameterInfo;
import de.tsenger.animamea.asn1.PaceInfo;
import de.tsenger.animamea.asn1.PublicKey;
import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.crypto.AmCryptoProvider;
import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.tools.HexString;

/**
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
	
	
	public PaceOperator(PaceInfo pi, String password, int pwRef) {
		
		protocolOIDString = pi.getProtocolOID();		
		passwordRef = pwRef;
		
		if (passwordRef==1) passwordBytes = calcSHA1(password.getBytes());
		else passwordBytes = password.getBytes();
				
		getStandardizedDomainParameters(pi.getParameterId());
		
		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())||protocolOIDString.startsWith(id_PACE_DH_IM.toString())) pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())||protocolOIDString.startsWith(id_PACE_ECDH_IM.toString())) pace = new PaceECDH(ecdhParameters);
		
		getCryptoInformation(pi);
	}
	
	
	public PaceOperator(PaceInfo pi, PaceDomainParameterInfo pdpi, String password, int pwRef) throws Exception {
		
		protocolOIDString = pi.getProtocolOID();
		passwordRef = pwRef;
				
		if (pi.getParameterId()>=0 && pi.getParameterId()<= 31)
			throw new Exception("ParameterID number 0 to 31 is used for standardized domain parameters!");
		if (pi.getParameterId() != pdpi.getParameterId())
			throw new Exception("PaceInfo doesn't match the PaceDomainParameterInfo");
		
		if (pwRef==1) passwordBytes = calcSHA1(password.getBytes());
		else passwordBytes = password.getBytes();
		
		getProprietaryDomainParameters(pdpi);
		
		if (protocolOIDString.startsWith(id_PACE_DH_GM.toString())||protocolOIDString.startsWith(id_PACE_DH_IM.toString())) pace = new PaceDH(dhParameters);
		else if (protocolOIDString.startsWith(id_PACE_ECDH_GM.toString())||protocolOIDString.startsWith(id_PACE_ECDH_IM.toString())) pace = new PaceECDH(ecdhParameters);
		
		getCryptoInformation(pi);
	}
	
	
	public SecureMessaging performPace(AmCardHandler ch) throws Exception {
		cardHandler = ch;
		
		
		//send MSE:SetAT
		ResponseAPDU rapdu = ch.transceive(new CommandAPDU(getMSESetAT(2)));
		//TODO in eigene Methode auslagern und Fehlermeldung von MSE:SetAT abfangen
		
		//send first GA and get nonce
		byte[] nonce_z = getNonce().getEncryptedNonce80();
		byte[] nonce_s = decryptNonce(nonce_z);
		byte[] X1 = pace.getX1(nonce_s);
		
		// X1 zur Karte schicken und Y1 empfangen
		byte[] Y1 = mapNonce(X1).getMappingData82(); 
		
		byte[] X2 = pace.getX2(Y1);
		// X2 zur Karte schicken und Y2 empfangen.
		byte[] Y2 = performKeyAgreement(X2).getEphemeralPK84();

		byte[] S = pace.getSharedSecret_K(Y2);
		byte[] kenc = getKenc(S);
		byte[] kmac  = getKmac(S);
		
		// Authentication Token T_PCD berechnen 
		PublicKey pkpcd = new PublicKey(protocolOIDString, Y2);	
		byte[] tpcd = crypto.getMAC(kmac, pkpcd.getEncoded());
		
		// Authentication Token zur Karte schicken
		byte[] tpicc = performMutualAuthentication(tpcd).getAuthToken86();
		
		// Authentication Token T_PICC berechnen 
		PublicKey pkpicc = new PublicKey(protocolOIDString, X2);
		byte[] tpicc_strich = crypto.getMAC(kmac, pkpicc.getEncoded());
		
		//Prüfe ob tpicc = t'picc=MAC(kmac,X2)
		if (!Arrays.areEqual(tpicc, tpicc_strich)) throw new Exception("Authentication Tokens are different");
		
		
		
		return null;
	}
	
	private DynamicAuthenticationData performMutualAuthentication(byte[] authToken) throws Exception {
		
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
		if (resp.getData()==null) throw new Exception("perform Key Agreement returns: "+HexString.bufferToHex(resp.getBytes()));
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}
	
	
	/**
	 * @return
	 * @throws Exception 
	 */
	private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK) throws Exception {
		
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
		if (resp.getData()==null) throw new Exception("perform Key Agreement returns: "+HexString.bufferToHex(resp.getBytes()));
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}


	/**
	 * @return
	 * @throws Exception 
	 */
	private DynamicAuthenticationData mapNonce(byte[] mappingData) throws Exception {
				
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
		if (resp.getData()==null) throw new Exception("Map nonce returns: "+HexString.bufferToHex(resp.getBytes()));
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}


	private byte[] getMSESetAT(int terminalType) {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_PACE);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(passwordRef);
		switch (terminalType) {
			case 0: break;
			case 1: mse.setISChat(); break;
			case 2: mse.setATChat(); break;
			case 3: mse.setSTChat(); break;
		}
		return mse.getBytes();
	}
	
	/**
	 * Send a plain General Authentication Command to get a encrypted nonce from the card.
	 * @return
	 * @throws Exception
	 */
	private DynamicAuthenticationData getNonce() throws Exception {
		CommandAPDU capdu = new CommandAPDU(Hex.decode("10860000027C0000"));
		ResponseAPDU resp = cardHandler.transceive(capdu);
		if (resp.getData()==null) throw new Exception("Get nonce returns: "+HexString.bufferToHex(resp.getBytes()));
		DynamicAuthenticationData dad = new DynamicAuthenticationData();
		dad.decode(resp.getData());
		return dad;
	}
	
	//TODO change to private
	public byte[] decryptNonce(byte[] z) {
	
		byte[] derivatedPassword = null;
		try {
			derivatedPassword = getKey(keyLength, passwordBytes, 3);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return crypto.decryptBlock(derivatedPassword, z);
	}
	
	//TODO change to private
	public byte[] getKenc(byte[] sharedSecret_S){
		try {
			return getKey(keyLength, sharedSecret_S, 1);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	//TODO change to private
	public byte[] getKmac(byte[] sharedSecret_S){
		try {
			return getKey(keyLength, sharedSecret_S, 2);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	private byte[] getKey(int keyLength, byte[] K, int c) throws Exception{
		
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
	
	
	// Funktioniert momentan nur mit EC
	private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi) throws Exception {
		if (pdpi.getDomainParameter().getAlgorithm().toString().contains(BSIObjectIdentifiers.id_ecc.toString())) {
			ASN1Sequence seq = (ASN1Sequence) pdpi.getDomainParameter().getParameters().getDERObject().toASN1Object();
			ecdhParameters = new X9ECParameters(seq);
		} else
			throw new Exception("Can't decode properietary domain parameters in PaceDomainParameterInfo!");
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
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge für PACE 
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
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_128.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_192.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(id_PACE_DH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_DH_IM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_GM_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(id_PACE_ECDH_IM_AES_CBC_CMAC_256.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}
	

}
