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

package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
/**
 * @author Tobias Senger (tobias@t-senger.de)
 *
 */
public interface BSIObjectIdentifiers {

	public static final String bsi_de = "0.4.0.127.0.7";

	// PACE OIDs
	public static final String id_PACE = new String(bsi_de + ".2.2.4");

	public static final ASN1ObjectIdentifier id_PACE_DH_GM = new ASN1ObjectIdentifier(
			id_PACE + ".1");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_PACE_DH_GM + ".1");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_PACE_DH_GM + ".2");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_PACE_DH_GM + ".3");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_PACE_DH_GM + ".4");

	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM = new ASN1ObjectIdentifier(
			id_PACE + ".2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_PACE_ECDH_GM + ".1");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_GM + ".2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_GM + ".3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_GM + ".4");

	public static final ASN1ObjectIdentifier id_PACE_DH_IM = new ASN1ObjectIdentifier(
			id_PACE + ".3");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_PACE_DH_IM + ".1");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_PACE_DH_IM + ".2");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_PACE_DH_IM + ".3");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_PACE_DH_IM + ".4");

	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM = new ASN1ObjectIdentifier(
			id_PACE + ".4");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_PACE_ECDH_IM + ".1");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_IM + ".2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_IM + ".3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_IM + ".4");
	
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM = new ASN1ObjectIdentifier(
			id_PACE + ".6");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_CAM + ".2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_CAM + ".3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_PACE_ECDH_CAM + ".4");

	// Chip Authentication OIDs

	public static final String id_CA = new String(bsi_de + ".2.2.3");

	public static final ASN1ObjectIdentifier id_CA_DH = new ASN1ObjectIdentifier(
			id_CA + ".1");
	public static final ASN1ObjectIdentifier id_CA_DH_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_CA_DH + ".1");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_CA_DH + ".2");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_CA_DH + ".3");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_CA_DH + ".4");

	public static final ASN1ObjectIdentifier id_CA_ECDH = new ASN1ObjectIdentifier(
			id_CA + ".2");
	public static final ASN1ObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new ASN1ObjectIdentifier(
			id_CA_ECDH + ".1");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_128 = new ASN1ObjectIdentifier(
			id_CA_ECDH + ".2");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_192 = new ASN1ObjectIdentifier(
			id_CA_ECDH + ".3");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_256 = new ASN1ObjectIdentifier(
			id_CA_ECDH + ".4");

	// Chip Authentication Public Key OIDs

	public static final String id_PK = new String(bsi_de + ".2.2.1");
	public static final ASN1ObjectIdentifier id_PK_DH = new ASN1ObjectIdentifier(
			id_PK + ".1");
	public static final ASN1ObjectIdentifier id_PK_ECDH = new ASN1ObjectIdentifier(
			id_PK + ".2");

	// Terminal Authentication OIDs
	public static final String id_TA = new String(bsi_de + ".2.2.2");

	public static final ASN1ObjectIdentifier id_TA_RSA = new ASN1ObjectIdentifier(
			id_TA + ".1");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_1 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".1");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_256 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".2");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_1 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".3");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_256 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".4");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_512 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".5");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_512 = new ASN1ObjectIdentifier(
			id_TA_RSA + ".6");

	public static final ASN1ObjectIdentifier id_TA_ECDSA = new ASN1ObjectIdentifier(
			id_TA + ".2");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_1 = new ASN1ObjectIdentifier(
			id_TA_ECDSA + ".1");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_224 = new ASN1ObjectIdentifier(
			id_TA_ECDSA + ".2");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_256 = new ASN1ObjectIdentifier(
			id_TA_ECDSA + ".3");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_384 = new ASN1ObjectIdentifier(
			id_TA_ECDSA + ".4");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_512 = new ASN1ObjectIdentifier(
			id_TA_ECDSA + ".5");

	// Restricted Identification OIDs
	public static final String id_RI = new String(bsi_de + ".2.2.5");

	public static final ASN1ObjectIdentifier id_RI_DH = new ASN1ObjectIdentifier(
			id_RI + ".1");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_1 = new ASN1ObjectIdentifier(
			id_RI_DH + ".1");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_224 = new ASN1ObjectIdentifier(
			id_RI_DH + ".2");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_256 = new ASN1ObjectIdentifier(
			id_RI_DH + ".3");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_384 = new ASN1ObjectIdentifier(
			id_RI_DH + ".4");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_512 = new ASN1ObjectIdentifier(
			id_RI_DH + ".5");

	public static final ASN1ObjectIdentifier id_RI_ECDH = new ASN1ObjectIdentifier(
			id_RI + ".2");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_1 = new ASN1ObjectIdentifier(
			id_RI_ECDH + ".1");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_224 = new ASN1ObjectIdentifier(
			id_RI_ECDH + ".2");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_256 = new ASN1ObjectIdentifier(
			id_RI_ECDH + ".3");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_384 = new ASN1ObjectIdentifier(
			id_RI_ECDH + ".4");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_512 = new ASN1ObjectIdentifier(
			id_RI_ECDH + ".5");

	// CardInfoLocator OID
	public static final ASN1ObjectIdentifier id_CI = new ASN1ObjectIdentifier(
			bsi_de + ".2.2.6");

	// eIDSecurityInfo
	public static final ASN1ObjectIdentifier id_eIDSecurity = new ASN1ObjectIdentifier(
			bsi_de + ".2.2.7");

	// PrivilegedTerminalInfo
	public static final ASN1ObjectIdentifier id_PT = new ASN1ObjectIdentifier(
			bsi_de + ".2.2.8");

	// Roles
	public static final ASN1ObjectIdentifier id_roles = new ASN1ObjectIdentifier(
			bsi_de + ".3.1.2");

	public static final ASN1ObjectIdentifier id_IS = new ASN1ObjectIdentifier(
			id_roles + ".1");
	public static final ASN1ObjectIdentifier id_AT = new ASN1ObjectIdentifier(
			id_roles + ".2");
	public static final ASN1ObjectIdentifier id_ST = new ASN1ObjectIdentifier(
			id_roles + ".3");

	// Standardized Domain Parameters
	public static final ASN1ObjectIdentifier standardizedDomainParameters = new ASN1ObjectIdentifier(
			bsi_de + ".1.2");

	// Elliptic Curve OIDs (see BSI TR-03111 V1.11)
	public static final ASN1ObjectIdentifier id_ecc = new ASN1ObjectIdentifier(
			bsi_de + ".1.1");
	public static final ASN1ObjectIdentifier ansi_X9_62 = new ASN1ObjectIdentifier(
			"1.2.840.10045");

	public static final ASN1ObjectIdentifier id_publicKeyType = new ASN1ObjectIdentifier(
			ansi_X9_62 + ".2");
	public static final ASN1ObjectIdentifier id_ecPublicKey = new ASN1ObjectIdentifier(
			id_publicKeyType + ".1");

	public static final ASN1ObjectIdentifier id_ecTLVKeyFormat = new ASN1ObjectIdentifier(
			id_ecc + ".2.2");
	public static final ASN1ObjectIdentifier id_ecTLVPublicKey = new ASN1ObjectIdentifier(
			id_ecTLVKeyFormat + ".1");

	public static final ASN1ObjectIdentifier ecdsa_plain_signatures = new ASN1ObjectIdentifier(
			id_ecc + ".4.1");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA1 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".1");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA224 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".2");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA256 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".3");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA384 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".4");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA512 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".5");
	public static final ASN1ObjectIdentifier ecdsa_plain_RIPEMD160 = new ASN1ObjectIdentifier(
			ecdsa_plain_signatures + ".6");

	public static final ASN1ObjectIdentifier id_ecSigType = new ASN1ObjectIdentifier(
			ansi_X9_62 + ".4");
	public static final ASN1ObjectIdentifier ecdsa_with_Sha1 = new ASN1ObjectIdentifier(
			id_ecSigType + ".1");
	public static final ASN1ObjectIdentifier ecdsa_with_Specified = new ASN1ObjectIdentifier(
			id_ecSigType + ".3");
	public static final ASN1ObjectIdentifier ecdsa_with_Sha224 = new ASN1ObjectIdentifier(
			ecdsa_with_Specified + ".1");
	public static final ASN1ObjectIdentifier ecdsa_with_Sha256 = new ASN1ObjectIdentifier(
			ecdsa_with_Specified + ".2");
	public static final ASN1ObjectIdentifier ecdsa_with_Sha384 = new ASN1ObjectIdentifier(
			ecdsa_with_Specified + ".3");
	public static final ASN1ObjectIdentifier ecdsa_with_Sha512 = new ASN1ObjectIdentifier(
			ecdsa_with_Specified + ".4");

	public static final ASN1ObjectIdentifier ecka_eg = new ASN1ObjectIdentifier(
			id_ecc + ".5.1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF = new ASN1ObjectIdentifier(
			ecka_eg + ".1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA1 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA224 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".2");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA256 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".3");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA384 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".4");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA512 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".5");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_RIPEMD160 = new ASN1ObjectIdentifier(
			ecka_eg_X963KDF + ".6");

	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF = new ASN1ObjectIdentifier(
			ecka_eg + ".2");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_3DES = new ASN1ObjectIdentifier(
			ecka_eg_SessionKDF + ".1");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES128 = new ASN1ObjectIdentifier(
			ecka_eg_SessionKDF + ".2");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES192 = new ASN1ObjectIdentifier(
			ecka_eg_SessionKDF + ".3");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES256 = new ASN1ObjectIdentifier(
			ecka_eg_SessionKDF + ".4");

	public static final ASN1ObjectIdentifier ecka_dh = new ASN1ObjectIdentifier(
			id_ecc + ".5.2");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF = new ASN1ObjectIdentifier(
			ecka_dh + ".1");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA1 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".1");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA224 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".2");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA256 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".3");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA384 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".4");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA512 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".5");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_RIPEMD160 = new ASN1ObjectIdentifier(
			ecka_dh_X963KDF + ".6");

	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF = new ASN1ObjectIdentifier(
			ecka_dh + ".2");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_3DES = new ASN1ObjectIdentifier(
			ecka_dh_SessionKDF + ".1");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES128 = new ASN1ObjectIdentifier(
			ecka_dh_SessionKDF + ".2");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES192 = new ASN1ObjectIdentifier(
			ecka_dh_SessionKDF + ".3");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES256 = new ASN1ObjectIdentifier(
			ecka_dh_SessionKDF + ".4");

}
