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
package de.tsenger.animamea.bac;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.apache.log4j.Logger;

import de.tsenger.animamea.AmCardHandler;
import de.tsenger.animamea.crypto.AmCryptoException;
import de.tsenger.animamea.iso7816.SecureMessaging;
import de.tsenger.animamea.iso7816.SecureMessagingException;
import de.tsenger.animamea.tools.HexString;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class BACOperator {
	
	private AmCardHandler cardHandler = null;
	
	static Logger logger = Logger.getLogger(BACOperator.class);
	
	public BACOperator(AmCardHandler ch) {
		cardHandler = ch;
	}
	
	public SecureMessaging doMutualAuthentication(String mrzInfo) throws SecureMessagingException, CardException, BACException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, AmCryptoException, IOException, NoSuchProviderException {
		byte[] rndicc = getChallenge();
		BAC bac = new BAC(mrzInfo,rndicc);
		byte[] maData = bac.getMutualAuthenticationData();
		byte[] muResponse = sendMutualAuthenticate(maData);
		return bac.establishBAC(muResponse);
	}
	
	/**
     * Sends a getChallenge CommandAPDU to the MRTD
     *
     * @return byte[] Array with data from Response. Contains RND.ICC <p>
	 * @throws CardException 
	 * @throws SecureMessagingException 
	 * @throws BACException 
     */
    private byte[] getChallenge() throws SecureMessagingException, CardException, BACException {
        
        byte[] cmd = { (byte)0x00, (byte)0x84, (byte)0x00, (byte)0x00, (byte)0x08};
        CommandAPDU capdu = new CommandAPDU(cmd);
                
        ResponseAPDU resp = cardHandler.transceive(capdu);
        if (!(resp.getSW() == 0x9000 ))
			throw new BACException("Get challenge failed! SW: " + HexString.bufferToHex(resp.getBytes()));
		
        return resp.getData();
//        return new byte[] {(byte)0x46, (byte)0x08, (byte)0xF9, (byte)0x19, (byte)0x88, (byte)0x70, (byte)0x22, (byte)0x12};
    }
    
    private byte[] sendMutualAuthenticate(byte[] data) throws IOException, SecureMessagingException, CardException, BACException{
        
        byte[] ma_cmd= {(byte)0x00, (byte)0x82, (byte)0x00, (byte)0x00, (byte)(data.length)};
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(ma_cmd);
        bos.write(data);
        bos.write(0x28);
        
        byte[] capduBytes = bos.toByteArray();
        
        
        CommandAPDU capdu= new CommandAPDU(capduBytes);
        logger.info("MutualAuthentication Command: \n"+HexString.bufferToHex(capdu.getBytes()));
       
        ResponseAPDU resp = cardHandler.transceive(capdu);
        
        if (resp.getSW() != 0x9000) {
                logger.error("called method mutualAuthenticate failed! SW: "+HexString.bufferToHex(resp.getBytes()));
                throw new BACException("mutualAuthentication failed!");
        }
        
        return resp.getData();
//      return new byte[] {(byte)0x46, (byte)0xB9, (byte)0x34, (byte)0x2A, (byte)0x41, (byte)0x39, (byte)0x6C, (byte)0xD7,
//      (byte)0x38, (byte)0x6B, (byte)0xF5, (byte)0x80, (byte)0x31, (byte)0x04, (byte)0xD7, (byte)0xCE,
//      (byte)0xDC, (byte)0x12, (byte)0x2B, (byte)0x91, (byte)0x32, (byte)0x13, (byte)0x9B, (byte)0xAF,
//      (byte)0x2E, (byte)0xED, (byte)0xC9, (byte)0x4E, (byte)0xE1, (byte)0x78, (byte)0x53, (byte)0x4F,
//      (byte)0x2F, (byte)0x2D, (byte)0x23, (byte)0x5D, (byte)0x07, (byte)0x4D, (byte)0x74, (byte)0x49};

    }

}
