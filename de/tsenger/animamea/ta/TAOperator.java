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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.asn1.CVCertificate;
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
	private String car = null;
	private CertificateProvider certProv = null;

	/** 
	 * Konstruktor
	 * @param ch AmCardHandler-Instanz über welches die Kartenkommandos gesendet werden.
	 */
	public TAOperator(AmCardHandler ch) {
		cardHandler  = ch;
	}
	
	/** Initialisiert den TA Operator mit der initialen CAR aus PACE und einem
	 * Zertifikats-Provider welche die passenden Zertifikate bereitstellt.
	 * @param car Certifate Authority Reference aus PACE
	 * @param certProv 
	 */
	public void initialize(String car, CertificateProvider certProv) {
		this.car = car;
		this.certProv = certProv;
	}
	
	/**
	 * Führt alle Schritte der Terminal Authentisierung durch. 
	 * TODO: Link-Zertifikate werden zur Zeit nicht unterstützt
	 */
	public void performTA() throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, IOException, CardException, SecureMessagingException {
		// 1. MSE:Set DST
		sendMSESetDST(certProv.getDVCert().getBody().getCAR()); //CAR muss mit dem aus PACE übereinstimmen.
		// 2. PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getDVCert());
		
		// MSE:Set DST 
		sendMSESetDST(certProv.getTerminalCert().getBody().getCAR());
		// PSO:Verify Certificate
		sendPSOVerifyCertificate(certProv.getTerminalCert());
		
		// 3. MSE:Set AT
//		sendMSESetAT();
		System.out.println("TA OID: "+certProv.getTerminalCert().getBody().getPublicKey().getOID());
		
	}
	
	/**
	 * 
	 */
//	private void sendMSESetAT() {
//		MSESetAT mse = new MSESetAT();
//		mse.setAT(MSESetAT.setAT_TA);
//		mse.setProtocol(protocolOIDString);
//		mse.setKeyReference(passwordRef);
//		
//	}

	/**
	 * @param dvCert
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
	 */
	private ResponseAPDU sendPSOVerifyCertificate(CVCertificate dvCert) throws InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, IOException, SecureMessagingException {
				
		byte[] header = Hex.decode("002A00BE");
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
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws DataLengthException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws CardException
	 * @throws SecureMessagingException
	 */
	private ResponseAPDU sendMSESetDST(String pubKeyRef) throws IOException, InvalidKeyException, DataLengthException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException, InvalidCipherTextException, CardException, SecureMessagingException {
	
		DERTaggedObject do83 = new DERTaggedObject(false, 0x03, new DEROctetString(pubKeyRef.getBytes()));
		byte[] data = do83.getDEREncoded();
		
		CommandAPDU setdst = new CommandAPDU(0x00,0x22,0x81,0xB6,data);
		
		return cardHandler.transceive(setdst);
	}

}
