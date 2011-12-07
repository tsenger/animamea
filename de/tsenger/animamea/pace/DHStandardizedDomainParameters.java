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

import java.math.BigInteger;

import org.bouncycastle.crypto.params.DHParameters;

/**
 * Standardisierte DH Domain Parameter für PACE
 * 
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public class DHStandardizedDomainParameters {

	public static DHParameters modp1024_160() {
		BigInteger p = new BigInteger(
				"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
						+ "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
						+ "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
						+ "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
						+ "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
						+ "DF1FB2BC2E4A4371", 16);
		BigInteger g = new BigInteger(
				"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
						+ "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
						+ "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
						+ "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
						+ "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
						+ "855E6EEB22B3B2E5", 16);
		BigInteger q = new BigInteger(
				"F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16);
		return new DHParameters(p, g, q);
	}

	public static DHParameters modp2048_224() {
		BigInteger p = new BigInteger(
				"AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1"
						+ "B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15"
						+ "EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC212"
						+ "9037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
						+ "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708"
						+ "B3BF8A317091883681286130BC8985DB1602E714415D9330"
						+ "278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486D"
						+ "CDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
						+ "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763"
						+ "C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71"
						+ "CF9DE5384E71B81C0AC4DFFE0C10E64F", 16);
		BigInteger g = new BigInteger(
				"AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF"
						+ "74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFA"
						+ "AB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7"
						+ "C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
						+ "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBE"
						+ "F180EB34118E98D119529A45D6F834566E3025E316A330EF"
						+ "BB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB"
						+ "10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
						+ "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269"
						+ "EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC0179"
						+ "81BC087F2A7065B384B890D3191F2BFA", 16);
		BigInteger q = new BigInteger(
				"801C0D34C58D93FE997177101F80535A4738CEBCBF389A99" + "B36371EB",
				16);
		return new DHParameters(p, g, q);
	}

	public static DHParameters modp2048_256() {
		BigInteger p = new BigInteger(
				"87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F2"
						+ "5D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30"
						+ "16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD"
						+ "5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
						+ "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C"
						+ "4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E"
						+ "F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D9"
						+ "67E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
						+ "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C3"
						+ "75F26375D7014103A4B54330C198AF126116D2276E11715F"
						+ "693877FAD7EF09CADB094AE91E1A1597", 16);
		BigInteger g = new BigInteger(
				"3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF2054"
						+ "07F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555"
						+ "BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18"
						+ "A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
						+ "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC83"
						+ "1D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55"
						+ "A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14"
						+ "C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
						+ "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6"
						+ "184B523D1DB246C32F63078490F00EF8D647D148D4795451"
						+ "5E2327CFEF98C582664B4C0F6CC41659", 16);
		BigInteger q = new BigInteger(
				"8CF83642A709A097B447997640129DA299B1A47D1EB3750B"
						+ "A308B0FE64F5FBD3", 16);
		return new DHParameters(p, g, q);
	}

}
