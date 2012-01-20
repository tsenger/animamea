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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.AmECPublicKey;
import de.tsenger.animamea.asn1.CVCertificate;
import de.tsenger.animamea.asn1.DomainParameter;
import de.tsenger.animamea.asn1.PublicKey;
import de.tsenger.animamea.iso7816.MSESetAT;
import de.tsenger.animamea.iso7816.SecureMessagingException;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class TAOperator {
	
	private AmCardHandler cardHandler = null;
	private final String car = null;
	private CertificateProvider certProv = null;
	private DomainParameter cadp = null;
	private byte[] pkpicc = null;
	private TerminalAuthentication ta = null;
	private byte[] ephemeralPKpcd = null;
	


	/** 
	 * Konstruktor
	 * @param ch AmCardHandler-Instanz über welches die Kartenkommandos gesendet werden.
	 */
	public TAOperator(AmCardHandler ch) {
		cardHandler  = ch;
	}
	
	/**
	 * Initialisiert den TA Operator mit der initialen CAR aus PACE und einem
	 * Zertifikats-Provider welche die passenden Zertifikate bereitstellt.
	 * 
	 * @param car Certifate Authority Reference aus PACE
	 * @param certProv
	 * @param cadpi
	 */
	public void initialize(CertificateProvider certProv, DomainParameter cadp, byte[] pkpicc) {
		this.certProv = certProv;
		this.cadp = cadp;
		this.pkpicc  = pkpicc;
		
		PublicKey cvcaPubKey = certProv.getCVCACert().getBody().getPublicKey();
		if(cvcaPubKey instanceof AmECPublicKey) {
			AmECPublicKey ecpk = (AmECPublicKey)cvcaPubKey;
			ta = new TerminalAuthenticationECDSA(cadp, ecpk, certProv.getPrivateKey().getKey());
		}
		
	}
	
	/**
	 * Führt alle Schritte der Terminal Authentisierung durch. 
	 * TODO: Link-Zertifikate werden zur Zeit nicht unterstützt
	 * @throws CardException 
	 * @throws SecureMessagingException 
	 * @throws NoSuchProviderException 
	 */
	public void performTA() throws TAException, SecureMessagingException, CardException {
				
		/*DV-Zertifikat*/
		
		// 1.1 MSE:Set DST
		sendMSESetDST(certProv.getDVCert().getBody().getCAR()); //TODO CAR muss mit dem aus PACE übereinstimmen. Hier wird das Zert aber direkt ausgewählt weil es weiß welches benötigt wird... 
		// 2.1 PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getDVCert());
		
		/*Terminal-Zertifikat*/
		
		// 1.2 MSE:Set DST 
		sendMSESetDST(certProv.getTerminalCert().getBody().getCAR());
		// 2.2 PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getTerminalCert());
		
		// 3. MSE:Set AT
		// Erzeuge den ephemeral Public Key des Terminals:
		ephemeralPKpcd = ta.getEphemeralPKpcd(); //Wird auch noch bei CA benötigt.
		
		// Komprimierte Version des ephemeralen Public Keys:
		byte[] compEphPK = comp(ephemeralPKpcd, cadp.getDPType());
		
		String protocolOID = certProv.getTerminalCert().getBody().getPublicKey().getOID();
		String pkname = certProv.getTerminalCert().getBody().getCHR();
		sendMSESetAT(protocolOID, pkname, compEphPK);
		
		// 4. Get Challenge
		byte[] rpicc = getChipChallenge();
		
		// 5. External Authenticate
		// Komprimierter ephemeraler Public Key des Chips aus PACE: ID_PICC = Comp(ephPK_PICC)
		byte[] idpicc = comp(pkpicc, cadp.getDPType());
		
		byte[] message = new byte[idpicc.length+rpicc.length+compEphPK.length];
		System.arraycopy(idpicc, 0, message, 0, idpicc.length);
		System.arraycopy(rpicc, 0, message, idpicc.length, rpicc.length);
		System.arraycopy(compEphPK, 0, message, idpicc.length+rpicc.length, compEphPK.length);
				
		byte[] signature = ta.sign(message);
		
		sendExternalAuthenticate(signature);

	}

	
	public byte[] getPKpcd() {
		return ephemeralPKpcd;
	}
	
	private byte[] comp(byte[] publicKeyBytes, String type) {
		if (type.equals("ECDH")) {
			byte[] compValue = new byte[(publicKeyBytes.length-1)/2];
			System.arraycopy(publicKeyBytes, 1, compValue, 0, compValue.length);
			return compValue;
		}
		else if (type.equals("DH")) {
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("SHA1");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			md.update(publicKeyBytes); 
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
		cardHandler.transceive(new CommandAPDU(mse.getBytes()));
		
		
	}

	/**
	 * @param dvCert
	 * @throws SecureMessagingException 
	 * @throws CardException 
	 */
	private ResponseAPDU sendPSOVerifyCertificate(CVCertificate dvCert) throws SecureMessagingException, CardException {
		
		byte[] certBody = dvCert.getBody().getDEREncoded();
		byte[] certSignature = dvCert.getSignature().getDEREncoded();
		
		byte[] data = new byte[certBody.length+certSignature.length];
		System.arraycopy(certBody, 0, data, 0, certBody.length);
		System.arraycopy(certSignature, 0, data, certBody.length, certSignature.length);
		
		
		CommandAPDU pso = new CommandAPDU(0x00, 0x2A, 0x00, 0xBE, data);
		
		return cardHandler.transceive(pso);
	}

	/**
	 * @param pubKeyRef
	 * @return
	 * @throws CardException
	 * @throws SecureMessagingException
	 */
	private ResponseAPDU sendMSESetDST(String pubKeyRef) throws SecureMessagingException, CardException{
	
		DERTaggedObject do83 = new DERTaggedObject(false, 0x03, new DEROctetString(pubKeyRef.getBytes()));
		byte[] data = do83.getDEREncoded();
		
		CommandAPDU setdst = new CommandAPDU(0x00,0x22,0x81,0xB6,data);
		
		return cardHandler.transceive(setdst);
	}



}
