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
package de.tsenger.animamea.ta;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.JCEDHPublicKey;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.AmPublicKey;
import de.tsenger.animamea.asn1.CVCertificate;
import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.tools.Converter;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class TAOperator {
	
	private AmCardHandler cardHandler = null;
	private CertificateProvider certProv = null;
	private DomainParameter cadp = null;
	private PublicKey pkpicc = null;
	private TerminalAuthentication ta = null;
	private PublicKey ephemeralPKpcd = null;
	
	static Logger logger = Logger.getLogger(TAOperator.class);
	


	/** 
	 * Konstruktor
	 * @param ch AmCardHandler-Instanz über welche die Kartenkommandos gesendet werden.
	 */
	public TAOperator(AmCardHandler ch) {
		cardHandler  = ch;
	}
	
	/**
	 * Initialisiert den id_TA SandOp mit einem Zertifikatsprovider, den id_CA-DomainParamatern 
	 * für die Berechnung des Public Key und dem Public Key aus id_PACE
	 * 
	 * @param certProv Zertifikat-Provider stellt die benötigten CV-Zertifikate bereit
	 * @param cadp Chip Authentication Domain Parameter zur Berechnung des Public Key während id_TA
	 * @param pkpicc Public Key aus id_PACE 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void initialize(CertificateProvider certProv, DomainParameter cadp, PublicKey pkpicc) throws IllegalArgumentException, IOException {
		this.certProv = certProv;
		this.cadp = cadp;
		this.pkpicc  = pkpicc;
		
		AmPublicKey cvcaPubKey = certProv.getCVCACert().getBody().getPublicKey();
		if(cvcaPubKey instanceof AmECPublicKey) {
			AmECPublicKey ecpk = (AmECPublicKey)cvcaPubKey;
			ta = new TerminalAuthenticationECDSA(cadp, ecpk, certProv.getPrivateKey().getKey());
		} //TODO RSA
		
	}
	
	/**
	 * Führt alle Schritte der Terminal Authentisierung durch. 
	 * TODO: Link-Zertifikate werden zur Zeit nicht unterstützt
	 * @return Keypair des Terminals 
	 * @throws CardException 
	 * @throws SecureMessagingException 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public KeyPair performTA() throws TAException, SecureMessagingException, CardException, IllegalArgumentException, IOException {
				
		/*DV-Zertifikat*/
		
		// 1.1 MSE:Set DST
		logger.debug("MSE Set DST: "+certProv.getDVCert().getBody().getCAR());
		//TODO CAR must match with return CAR value from PACE. Here we just use the CAR from our selected DV because this is the only one we have. If it doesn't match TA will fail.
		sendMSESetDST(certProv.getDVCert().getBody().getCAR()); 
		// 2.1 PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getDVCert());
		
		/*Terminal-Zertifikat*/
		
		// 1.2 MSE:Set DST 
		logger.debug("MSE Set DST: "+certProv.getTerminalCert().getBody().getCAR());
		sendMSESetDST(certProv.getTerminalCert().getBody().getCAR());
		// 2.2 PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getTerminalCert());
		
		// 3. MSE:Set id_AT
		// Erzeuge die ephemeralen Keys des Terminals:
		KeyPair pair = ta.getEphemeralPCDKeyPair();
		ephemeralPKpcd = pair.getPublic();
		
		// Komprimierte Version des ephemeralen Public Keys:
		byte[] compEphPK = comp(ephemeralPKpcd);
		
		String protocolOID = certProv.getTerminalCert().getBody().getPublicKey().getOID();
		String pkname = certProv.getTerminalCert().getBody().getCHR();
		sendMSESetAT(protocolOID, pkname, compEphPK);
		
		// 4. Get Challenge
		byte[] rpicc = getChipChallenge();
		
		// 5. External Authenticate
		// Komprimierter ephemeraler Public Key des Chips aus id_PACE: ID_PICC = Comp(ephPK_PICC)
		byte[] idpicc = comp(pkpicc);
		
		byte[] message = new byte[idpicc.length+rpicc.length+compEphPK.length];
		System.arraycopy(idpicc, 0, message, 0, idpicc.length);
		System.arraycopy(rpicc, 0, message, idpicc.length, rpicc.length);
		System.arraycopy(compEphPK, 0, message, idpicc.length+rpicc.length, compEphPK.length);
				
		byte[] signature = ta.sign(message);
		
		if (sendExternalAuthenticate(signature).getSW()!=0x9000) throw new TAException("External Authentication failed.");
		
		return pair;

	}
	
	private byte[] comp(java.security.PublicKey publicKey) {
		if (publicKey.getAlgorithm().equals("ECDH")) {
			BigInteger x = ((ECPublicKey)publicKey).getQ().getAffineXCoord().toBigInteger();
			return Converter.bigIntToByteArray(x);
		}
		else if (publicKey.getAlgorithm().equals("DH")) {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA1");
			} catch (NoSuchAlgorithmException e) {}
			md.update(((JCEDHPublicKey)publicKey).getY().toByteArray()); 
	      	return md.digest();
		}
		return null;
	}
	
	/**
	 * @return
	 * @throws SecureMessagingException
	 * @throws CardException
	 */
	private byte[] getChipChallenge() throws  SecureMessagingException, CardException {
		CommandAPDU capdu = new CommandAPDU(Hex.decode("0084000008"));
		ResponseAPDU resp = cardHandler.transceive(capdu);
		return resp.getData();
	}

	
	/**
	 * @param signature
	 * @return
	 * @throws SecureMessagingException
	 * @throws CardException
	 */
	private ResponseAPDU sendExternalAuthenticate(byte[] signature) throws SecureMessagingException, CardException {
		
		CommandAPDU extAuth = new CommandAPDU(0x00,0x82,0x00,0x00,signature);
		return cardHandler.transceive(extAuth);
	}
	
	

	/**
	 * @throws SecureMessagingException 
	 * @throws CardException 
	 */
	private void sendMSESetAT(String protocolOIDString, String pkname, byte[] epubkey) throws SecureMessagingException, CardException {
		MSESetAT mse = new MSESetAT();
		mse.setAT(MSESetAT.setAT_TA);
		mse.setProtocol(protocolOIDString);
		mse.setKeyReference(pkname);
		mse.setEphemeralPublicKey(epubkey);
		cardHandler.transceive(mse.getCommandAPDU());
		
		
	}

	/**
	 * @param dvCert
	 * @throws SecureMessagingException 
	 * @throws CardException 
	 * @throws TAException 
	 */
	private ResponseAPDU sendPSOVerifyCertificate(CVCertificate dvCert) throws SecureMessagingException, CardException, TAException {
		
		byte[] certBody = null;
		byte[] certSignature = null;
		byte[] data = null;
		try {
			certBody = dvCert.getBody().getEncoded(ASN1Encoding.DER);
			certSignature = dvCert.getSignature().getEncoded(ASN1Encoding.DER);
			
			data = new byte[certBody.length+certSignature.length];
			System.arraycopy(certBody, 0, data, 0, certBody.length);
			System.arraycopy(certSignature, 0, data, certBody.length, certSignature.length);
			
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
		
		CommandAPDU pso = new CommandAPDU(0x00, 0x2A, 0x00, 0xBE, data);
		ResponseAPDU resp = cardHandler.transceive(pso);
		if (resp.getSW1()!=0x90) throw new TAException("PSO:Verify failed "+HexString.bufferToHex(resp.getBytes()));

		return resp;
	}

	/**
	 * @param pubKeyRef
	 * @return
	 * @throws CardException
	 * @throws SecureMessagingException
	 * @throws TAException 
	 */
	private ResponseAPDU sendMSESetDST(String pubKeyRef) throws SecureMessagingException, CardException, TAException{
	
		DERTaggedObject do83 = new DERTaggedObject(false, 0x03, new DEROctetString(pubKeyRef.getBytes()));
		byte[] data = null;
		
		try {
			data = do83.getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			logger.error(e.getLocalizedMessage());
		}
		
		CommandAPDU setdst = new CommandAPDU(0x00,0x22,0x81,0xB6,data);
		
		ResponseAPDU resp = cardHandler.transceive(setdst);
		if (resp.getSW1()!=0x90) throw new TAException("MSE:Set id_AT failed "+HexString.bufferToHex(resp.getBytes()));
		
		return resp;
	}



}
