package de.tsenger.animamea.pace;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Crypto {
	/**
	 * Diese Methode füllt ein Byte-Array mit dem Wert 0x80 und mehreren 0x00
	 * bis die Länge des übergebenen Byte-Array ein Vielfaches von 8 ist. Dies
	 * ist die ISO9797-1 Padding-Methode 2.
	 * 
	 * @param data
	 *            Das Byte-Array welches aufgefüllt werden soll.
	 * @return Das gefüllte Byte-Array.
	 */
	public static byte[] padByteArray(byte[] data) {

		int i = 0;
		byte[] tempdata = new byte[data.length + 8];

		for (i = 0; i < data.length; i++) {
			tempdata[i] = data[i];
		}

		tempdata[i] = (byte) 0x80;

		for (i = i + 1; ((i) % 8) != 0; i++) {
			tempdata[i] = (byte) 0;
		}

		byte[] filledArray = new byte[i];
		System.arraycopy(tempdata, 0, filledArray, 0, i);
		return filledArray;
	}

	/**
	 * Entfernt aus dem übergebenen Byte-Array das Padding nach ISO9797-1
	 * Padding-Methode 2. Dazu werden aus dem übergebenen Byte-Array von hinten
	 * beginnend Bytes mit dem Wert 0x00 gelöscht, sowie die der Wert 0x80 der
	 * das Padding markiert.
	 * 
	 * @param Byte
	 *            -Array aus dem das Padding entfernt werden soll
	 * @return bereinigtes Byte-Array
	 */
	public static byte[] removePadding(byte[] b) {
		byte[] rd = null;
		int i = b.length - 1;
		do {
			i--;
		} while (b[i] == (byte) 0x00);

		if (b[i] == (byte) 0x80) {
			rd = new byte[i];
			System.arraycopy(b, 0, rd, 0, rd.length);
			return rd;
		}
		return b;
	}

	/**
	 * Berechnet die XOR-Verknüpfung von zwei Bytes-Arrays der selben Länge
	 * 
	 * @param a
	 *            Byte-Array A
	 * @param b
	 *            Byte-Array B
	 * @return XOR-Verknüpfung von a und b
	 * @throws IllegalArgumentException
	 *             falls die beiden Byte-Arrays nicht die gleiche Länge haben
	 */
	public static byte[] xorArray(byte[] a, byte[] b)
			throws IllegalArgumentException {
		if (b.length < a.length)
			throw new IllegalArgumentException(
					"length of byte [] b must be >= byte [] a");
		byte[] c = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}
		return c;
	}

	/**
	 * Verschlüsselt oder Entschlüsselt das übergebene Byte-Array 'plaintext'
	 * mit Hilfe des Triple-DES Algorithmus. Der Schlüssel wird in der Variable
	 * 'key' erwartet. IV = 0
	 * 
	 * @param encrypt
	 *            Wenn 'true' werden die Daten in data verschlüsselt, ansonsten
	 *            entschlüsselt.
	 * @param key
	 *            Der 3DES-Schlüssel als Byte-Array.
	 * @param data
	 *            Das zu verschlüsselnde Byte-Array
	 * @return Chiffre
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static byte[] tripleDES(boolean encrypt, byte[] key, byte[] data)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher des;
		byte[] result = null;
		IvParameterSpec iv = new IvParameterSpec(new byte[] { (byte) 0,
				(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
				(byte) 0 });
		SecretKeySpec skey = new SecretKeySpec(key, "DESede");

		des = Cipher.getInstance("DESede/CBC/NoPadding");
		if (encrypt) {
			des.init(Cipher.ENCRYPT_MODE, skey, iv);
		} else {
			des.init(Cipher.DECRYPT_MODE, skey, iv);
		}
		result = des.doFinal(data);

		return result;
	}



	/**
	 * Berechnet den SHA1-Wert des ÃŒbergebenen Bytes-Array
	 * 
	 * @param input
	 *            Byte-Array des SHA1-Wert berechnet werden soll
	 * @return SHA1-Wert vom ÃŒbergebenen Byte-Array
	 */
	public static byte[] calculateSHA1(byte[] input) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException ex) {
		}

		md.update(input);
		return md.digest();
	}

}
