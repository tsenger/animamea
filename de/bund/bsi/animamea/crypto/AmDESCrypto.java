/**
 * 
 */
package de.bund.bsi.animamea.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
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
public class AmDESCrypto extends AmCryptoProvider {

	
	public static int blockSize = 8;
	private byte[] keyBytes;
	private KeyParameter keyP = null;
	private byte[] IV = null;
	private byte[] sscBytes = null;


	private void initCiphers(byte[] key, byte[] iv) {
		// get the keyBytes
		keyBytes = new byte[key.length];
		System.arraycopy(key, 0, keyBytes, 0, key.length);
		
		// get the IV
		IV = new byte[blockSize];
		System.arraycopy(iv, 0, IV, 0, iv.length);
		
		keyP = new KeyParameter(keyBytes);
		
		encryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()), new ISO7816d4Padding());
        decryptCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()), new ISO7816d4Padding());
        
        // create the IV parameter
     	ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);
        
        encryptCipher.init(true, parameterIV);
        decryptCipher.init(false, parameterIV);
	}
	
	/**
	 * Initialisiert die Crypto-Engine mit dem angegebenen Schlüssel
	 * und dem Send Sequence Counter
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
	}


	/* (non-Javadoc)
	 * @see de.bund.bsi.animamea.crypto.AmCryptoProvider#getMAC(byte[])
	 */
	@Override
	public byte[] getMAC(byte[] data) {
		
		byte[] n = new byte[8+data.length];
		System.arraycopy(sscBytes, 0, n, 0, 8);
		System.arraycopy(data, 0, n, 8, data.length);
		
		BlockCipher cipher = new DESEngine();
        Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());
        
     	ParametersWithIV parameterIV = new ParametersWithIV(keyP, IV);
     	
        mac.init(parameterIV);        
        mac.update(n, 0, n.length);

        byte[] out = new byte[8];

        mac.doFinal(out, 0);
        
		return out;
	}

}
