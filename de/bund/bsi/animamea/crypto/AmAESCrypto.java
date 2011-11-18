/**
 * 
 */
package de.bund.bsi.animamea.crypto;

import static de.bund.bsi.animamea.tools.Converter.longToByteArray;

import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import de.bund.bsi.animamea.tools.Converter;

/**
 * @author Tobias Senger (tobias.senger@bsi.bund.de)
 * 
 */
public class AmAESCrypto extends AmCryptoProvider {

	private byte[] keyBytes = null;
	private KeyParameter keyP = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;
	
	public static int blockSize = 16;

	
	private void initCiphers(byte[] key, byte[] iv) {

		// get the keyBytes
		keyBytes = new byte[key.length];
		System.arraycopy(key, 0, keyBytes, 0, key.length);
		
		keyP = new KeyParameter(keyBytes);

		// get the IV
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
		
		// create the ciphers
		// AES block cipher in CBC mode with ISO7816d4 padding
		encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding() );

		decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
				new AESFastEngine()), new ISO7816d4Padding() );

		// create the IV parameter
		ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);

		encryptCipher.init(true, parameterIV);
		decryptCipher.init(false, parameterIV);
	}
	
	/**
	 * Initialisiert die Crypto-Engine mit dem angegebenen Schlüssel und einem
	 * aus dem Send Sequence Counter (SSC) berechneten Initialisierungsvektor
	 * (IV).
	 * 
	 * @param keyBytes
	 *            Schlüssel
	 * @param ssc
	 *            Send Sequence Counter
	 */
	@Override
	public void init(byte[] keyBytes, long ssc) {
		
		sscBytes = Converter.longToByteArray(ssc);
		
		initCiphers(keyBytes, new byte[blockSize]);
		byte[] iv = null;
		try {
			iv = encrypt(longToByteArray(ssc));
		} catch (DataLengthException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ShortBufferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		initCiphers(keyBytes, iv);
	}
	

	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(byte[] data) {
		
		byte[] n = new byte[8+data.length];
		System.arraycopy(sscBytes, 0, n, 0, 8);
		System.arraycopy(data, 0, n, 8, data.length);
		
		BlockCipher cipher = new AESFastEngine();
        Mac mac = new CMac(cipher, 64); //TODO Padding der Daten 
        
        ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);
        mac.init(parameterIV);
        
        mac.update(n, 0, n.length);

        byte[] out = new byte[8];

        mac.doFinal(out, 0);
        
		return out;
	}

}
