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
package de.tsenger.animamea.ca;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.JCEDHPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.AmDHPublicKey;
import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.BSIObjectIdentifiers;
import de.tsenger.animamea.asn1.ChipAuthenticationInfo;
import de.tsenger.animamea.asn1.ChipAuthenticationPublicKeyInfo;
import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.asn1.DynamicAuthenticationData;
import de.tsenger.animamea.crypto.AmAESCrypto;
import de.tsenger.animamea.crypto.AmCryptoProvider;
import de.tsenger.animamea.crypto.AmDESCrypto;
import de.tsenger.animamea.crypto.KeyDerivationFunction;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class CAOperator {
	
	private AmCardHandler ch = null;
	private PrivateKey ephSKPCD = null;
	private PublicKey ephPKPCD = null;
	private byte[] caPK = null;
	private DomainParameter dp = null;
	private int caPKref;
	private String protocol = null;
	private ChipAuthentication ca = null;
	private int keyLength;
	private AmCryptoProvider crypto = null;
	
	/**
	 * Constructor
	 * @param ch CardHandler 
	 */
	public CAOperator(AmCardHandler ch) {
		this.ch = ch;
	}
	
	public void initialize(ChipAuthenticationInfo caInfo, ChipAuthenticationPublicKeyInfo caPKInfo, KeyPair ephPCDKeyPair) throws CAException {
		this.protocol = caInfo.getProtocolOID().toString();
				
		this.caPK = caPKInfo.getPublicKey().getPublicKey();
		
		this.caPKref = caInfo.getKeyId();
		if (caPKref != caPKInfo.getKeyId()) throw new CAException("Key Identifier in ChipAuthenticationInfo and ChipAuthenticationPublicKeyInfo doesn't match");
		
		this.dp = new DomainParameter(caPKInfo.getPublicKey().getAlgorithm());
		
		if (dp.getDPType().equals("ECDH")) {
			ca = new ChipAuthenticationECDH(dp.getECParameter());
		} else if (dp.getDPType().equals("DH")) {
			ca = new ChipAuthenticationDH(dp.getDHParameter());
		}
		
		this.ephSKPCD = ephPCDKeyPair.getPrivate();
		this.ephPKPCD = ephPCDKeyPair.getPublic();
				
		getCryptoInformation(caInfo);
	}
	
	public SecureMessaging performCA() throws SecureMessagingException, CardException, CAException {
		//send MSE:Set id_AT
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_CA);
		mse.setProtocol(protocol);
		mse.setPrivateKeyReference(caPKref);
		ch.transceive(mse.getCommandAPDU());
		
		// General Authenticate
		DynamicAuthenticationData dad = sendGA(); //TODO Rückgabe der Karte prüfen (z.B. SW != 9000)
		
		//Schlüssel für Secure Messaging berechnen
		byte[] rnd_picc = dad.getDataObject(1);
		
		byte[] K = ca.getSharedSecret_K(ephSKPCD, caPK);
		
		byte[] kenc = null;
		byte[] kmac = null;
				
		switch (keyLength) {
		case 112: 	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getDESedeKey();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getDESedeKey();
					break;
		case 128:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES128Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES128Key();
					break;
		case 192:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES192Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES192Key();
					break;
		case 256:	kenc = new KeyDerivationFunction(K, rnd_picc, 1).getAES256Key();
					kmac = new KeyDerivationFunction(K, rnd_picc, 2).getAES256Key();
					break;
		}
		
		//Authentication Token vergleichen
		byte[] tpcd = calcToken(kmac, ephPKPCD);
		if (!Arrays.areEqual(tpcd, dad.getDataObject(2))) throw new CAException("Authentication Tokens are different. Cards Token:\n"+
		HexString.bufferToHex(dad.getDataObject(2))+"calculated Token:\n"+HexString.bufferToHex(tpcd));
				
		return new SecureMessaging(crypto, kenc, kmac, new byte[crypto.getBlockSize()]);
	}
	
	private byte[] calcToken(byte[] kmac, PublicKey data) {
		byte[] tpcd = null;
		if (ca instanceof ChipAuthenticationECDH) {
			ECPoint point = ((ECPublicKey)data).getQ();
			AmECPublicKey pk = new AmECPublicKey(protocol, point);
			tpcd = crypto.getMAC(kmac, pk.getEncoded());
		}
		else if (ca instanceof ChipAuthenticationDH) {
			BigInteger y = ((JCEDHPublicKey)data).getY();
			AmDHPublicKey pk = new AmDHPublicKey(protocol, y);
			tpcd = crypto.getMAC(kmac, pk.getEncoded());
		}
		return tpcd;
	}
	
	private DynamicAuthenticationData sendGA() throws SecureMessagingException, CardException {
		DynamicAuthenticationData dad80 = new DynamicAuthenticationData();
		dad80.addDataObject(0, ((ECPublicKey)ephPKPCD).getQ().getEncoded());
		
		byte[] dadBytes = null;
		try {
			dadBytes = dad80.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
		//TODO Length Expected steht hier auf 0xFF weil CommandAPDU den Wert 0x00 nicht berücksichtigt.
		ResponseAPDU resp = ch.transceive(new CommandAPDU(0x00, 0x86, 00, 00, dadBytes, 0xFF));
		
		DynamicAuthenticationData dad = new DynamicAuthenticationData(resp.getData());
		
		return dad;
	}
	
	/**
	 * Ermittelt anhand der ProtokollOID den Algorithmus und die Schlüssellänge
	 * für Chip Authentication
	 */
	private void getCryptoInformation(ChipAuthenticationInfo cai) {
		String protocolOIDString = cai.getProtocolOID();
		if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_3DES_CBC_CBC.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_3DES_CBC_CBC.toString())) {
			keyLength = 112;
			crypto = new AmDESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_128.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_128.toString())) {
			keyLength = 128;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_192.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_192.toString())) {
			keyLength = 192;
			crypto = new AmAESCrypto();
		} else if (protocolOIDString.equals(BSIObjectIdentifiers.id_CA_DH_AES_CBC_CMAC_256.toString())
				|| protocolOIDString.equals(BSIObjectIdentifiers.id_CA_ECDH_AES_CBC_CMAC_256.toString())) {
			keyLength = 256;
			crypto = new AmAESCrypto();
		}
	}

}
