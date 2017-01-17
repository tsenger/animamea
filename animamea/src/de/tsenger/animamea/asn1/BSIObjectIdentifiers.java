/**
 *  Copyright 2013, Tobias Senger
 *  
 *  This file is part of "certain".
 *
 *  certain is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  certain is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with certain.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.tsenger.animamea.asn1;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */

public interface BSIObjectIdentifiers {

	public static final ASN1ObjectIdentifier bsi_de = new ASN1ObjectIdentifier("0.4.0.127.0.7");
	
	/** Algorithms **/	
	public static final ASN1ObjectIdentifier algorithms = bsi_de.branch("1");	
	
	// ECC	
	public static final ASN1ObjectIdentifier id_ecc = algorithms.branch("1");
	
	public static final ASN1ObjectIdentifier keyType = id_ecc.branch("2");
	public static final ASN1ObjectIdentifier ecTLVKeyFormat = keyType.branch("2");
	public static final ASN1ObjectIdentifier ecTLVPublicKey = ecTLVKeyFormat.branch("1");
	public static final ASN1ObjectIdentifier ecPSPublicKey =  keyType.branch("3");
	
	public static final ASN1ObjectIdentifier signatures = id_ecc.branch("4");
	
	public static final ASN1ObjectIdentifier ecdsa_plain_signatures = signatures.branch("1");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA1 = ecdsa_plain_signatures.branch("1");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA224 = ecdsa_plain_signatures.branch("2");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA256 = ecdsa_plain_signatures.branch("3");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA384 = ecdsa_plain_signatures.branch("4");
	public static final ASN1ObjectIdentifier ecdsa_plain_SHA512 = ecdsa_plain_signatures.branch("5");
	public static final ASN1ObjectIdentifier ecdsa_plain_RIPEMD160 = ecdsa_plain_signatures.branch("6");
	
	public static final ASN1ObjectIdentifier ecgdsa_plain_signatures = signatures.branch("2");
	public static final ASN1ObjectIdentifier ecgdsa_plain_SHA224 = ecdsa_plain_signatures.branch("1");
	public static final ASN1ObjectIdentifier ecgdsa_plain_SHA256 = ecdsa_plain_signatures.branch("2");
	public static final ASN1ObjectIdentifier ecgdsa_plain_SHA384 = ecdsa_plain_signatures.branch("3");
	public static final ASN1ObjectIdentifier ecgdsa_plain_SHA512 = ecdsa_plain_signatures.branch("4");
	
	public static final ASN1ObjectIdentifier ecschnorr_plain_signatures = signatures.branch("3");
	public static final ASN1ObjectIdentifier ecschnorr_plain_SHA224 = ecdsa_plain_signatures.branch("1");
	public static final ASN1ObjectIdentifier ecschnorr_plain_SHA256 = ecdsa_plain_signatures.branch("2");
	public static final ASN1ObjectIdentifier ecschnorr_plain_SHA384 = ecdsa_plain_signatures.branch("3");
	public static final ASN1ObjectIdentifier ecschnorr_plain_SHA512 = ecdsa_plain_signatures.branch("4");
	
	public static final ASN1ObjectIdentifier key_establishment = id_ecc.branch("5");
	
	public static final ASN1ObjectIdentifier ecka_eg = key_establishment.branch("1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF = ecka_eg.branch("1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA1 = ecka_eg_X963KDF.branch("1");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA224 = ecka_eg_X963KDF.branch("2");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA256 = ecka_eg_X963KDF.branch("3");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA384 = ecka_eg_X963KDF.branch("4");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_SHA512 = ecka_eg_X963KDF.branch("5");
	public static final ASN1ObjectIdentifier ecka_eg_X963KDF_RIPEMD160 = ecka_eg_X963KDF.branch("6");

	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF = ecka_eg.branch("2");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_3DES = ecka_eg_SessionKDF.branch("1");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES128 = ecka_eg_SessionKDF.branch("2");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES192 = ecka_eg_SessionKDF.branch("3");
	public static final ASN1ObjectIdentifier ecka_eg_SessionKDF_AES256 = ecka_eg_SessionKDF.branch("4");

	public static final ASN1ObjectIdentifier ecka_dh = key_establishment.branch("2");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF = ecka_dh.branch("1");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA1 = ecka_dh_X963KDF.branch("1");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA224 = ecka_dh_X963KDF.branch("2");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA256 = ecka_dh_X963KDF.branch("3");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA384 = ecka_dh_X963KDF.branch("4");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_SHA512 = ecka_dh_X963KDF.branch("5");
	public static final ASN1ObjectIdentifier ecka_dh_X963KDF_RIPEMD160 = ecka_dh_X963KDF.branch("6");

	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF = ecka_dh.branch("2");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_3DES = ecka_dh_SessionKDF.branch("1");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES128 = ecka_dh_SessionKDF.branch("2");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES192 = ecka_dh_SessionKDF.branch("3");
	public static final ASN1ObjectIdentifier ecka_dh_SessionKDF_AES256 = ecka_dh_SessionKDF.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_KA = key_establishment.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_KA_GM = id_PACE_KA.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_KA_GM_SessionKDF_3DES = id_PACE_KA_GM.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_KA_GM_SessionKDF_AES128 = id_PACE_KA_GM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_KA_GM_SessionKDF_AES192 = id_PACE_KA_GM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_KA_GM_SessionKDF_AES256 = id_PACE_KA_GM.branch("4");
	
	// Standardized Domain Parameters
	public static final ASN1ObjectIdentifier standardizedDomainParameters = algorithms.branch("2");

	// Symmetric Ciphers
	public static final ASN1ObjectIdentifier symmetricCiphers = algorithms.branch("3");
	public static final ASN1ObjectIdentifier AES = symmetricCiphers.branch("1");
	
	public static final ASN1ObjectIdentifier authEncr = AES.branch("1");
	public static final ASN1ObjectIdentifier id_aes_CBC_CMAC_Param = authEncr.branch("1");
	public static final ASN1ObjectIdentifier id_aes_CBC_CMAC_128 = authEncr.branch("2");
	public static final ASN1ObjectIdentifier id_aes_CBC_CMAC_192 = authEncr.branch("3");
	public static final ASN1ObjectIdentifier id_aes_CBC_CMAC_256 = authEncr.branch("4");

	
	/** Protocols **/
	public static final ASN1ObjectIdentifier protocols = bsi_de.branch("2");
	
	// Internet
	public static final ASN1ObjectIdentifier internet = protocols.branch("1");
	public static final ASN1ObjectIdentifier LDAP = internet.branch("1");
	public static final ASN1ObjectIdentifier objectClasses = LDAP.branch("1");
	public static final ASN1ObjectIdentifier countryExt = LDAP.branch("2");
	public static final ASN1ObjectIdentifier serialNoExt = LDAP.branch("3");
	
	// Smartcard
	public static final ASN1ObjectIdentifier smartcard = protocols.branch("2");

	// PK
	public static final ASN1ObjectIdentifier PK = smartcard.branch("1");
	
	public static final ASN1ObjectIdentifier PK_DH =   PK.branch("1");
	public static final ASN1ObjectIdentifier PK_ECDH = PK.branch("2");
	public static final ASN1ObjectIdentifier PS_PK =   PK.branch("3");
	public static final ASN1ObjectIdentifier PS_PK_DH_Schnorr = PS_PK.branch("1");
	public static final ASN1ObjectIdentifier PS_PK_ECDH_ECSchnorr = PS_PK.branch("2");
	
	// Terminal Authentication 
	public static final ASN1ObjectIdentifier id_TA = smartcard.branch("2");

	public static final ASN1ObjectIdentifier id_TA_RSA = id_TA.branch("1");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_1 = id_TA_RSA.branch("1");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_256 = id_TA_RSA.branch("2");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_1 = id_TA_RSA.branch("3");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_256 = id_TA_RSA.branch("4");
	public static final ASN1ObjectIdentifier id_TA_RSA_v1_5_SHA_512 = id_TA_RSA.branch("5");
	public static final ASN1ObjectIdentifier id_TA_RSA_PSS_SHA_512 = id_TA_RSA.branch("6");

	public static final ASN1ObjectIdentifier id_TA_ECDSA = id_TA.branch("2");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_1 = id_TA_ECDSA.branch("1");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_224 = id_TA_ECDSA.branch("2");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_256 = id_TA_ECDSA.branch("3");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_384 = id_TA_ECDSA.branch("4");
	public static final ASN1ObjectIdentifier id_TA_ECDSA_SHA_512 = id_TA_ECDSA.branch("5");
	
	// Chip Authentication 
	public static final ASN1ObjectIdentifier id_CA = smartcard.branch("3");

	public static final ASN1ObjectIdentifier id_CA_DH = id_CA.branch("1");
	public static final ASN1ObjectIdentifier id_CA_DH_3DES_CBC_CBC = id_CA_DH.branch("1");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_128 = id_CA_DH.branch("2");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_192 = id_CA_DH.branch("3");
	public static final ASN1ObjectIdentifier id_CA_DH_AES_CBC_CMAC_256 = id_CA_DH.branch("4");

	public static final ASN1ObjectIdentifier id_CA_ECDH = id_CA.branch("2");
	public static final ASN1ObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = id_CA_ECDH.branch("1");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_128 = id_CA_ECDH.branch("2");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_192 = id_CA_ECDH.branch("3");
	public static final ASN1ObjectIdentifier id_CA_ECDH_AES_CBC_CMAC_256 = id_CA_ECDH.branch("4");
		
	// id_PACE
	public static final ASN1ObjectIdentifier id_PACE = smartcard.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_DH_GM = id_PACE.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_3DES_CBC_CBC = id_PACE_DH_GM.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_128 = id_PACE_DH_GM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_192 = id_PACE_DH_GM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_DH_GM_AES_CBC_CMAC_256 = id_PACE_DH_GM.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM = id_PACE.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_3DES_CBC_CBC = id_PACE_ECDH_GM.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_128 = id_PACE_ECDH_GM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_192 = id_PACE_ECDH_GM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_GM_AES_CBC_CMAC_256 = id_PACE_ECDH_GM.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_DH_IM = id_PACE.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_3DES_CBC_CBC = id_PACE_DH_IM.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_128 = id_PACE_DH_IM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_192 = id_PACE_DH_IM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_DH_IM_AES_CBC_CMAC_256 = id_PACE_DH_IM.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM = id_PACE.branch("4");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_3DES_CBC_CBC = id_PACE_ECDH_IM.branch("1");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_128 = id_PACE_ECDH_IM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_192 = id_PACE_ECDH_IM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_IM_AES_CBC_CMAC_256 = id_PACE_ECDH_IM.branch("4");

	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM = id_PACE.branch("6");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_128 = id_PACE_ECDH_IM.branch("2");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_192 = id_PACE_ECDH_IM.branch("3");
	public static final ASN1ObjectIdentifier id_PACE_ECDH_CAM_AES_CBC_CMAC_256 = id_PACE_ECDH_IM.branch("4");

	// Restricted Identification
	public static final ASN1ObjectIdentifier id_RI = smartcard.branch("5");

	public static final ASN1ObjectIdentifier id_RI_DH = id_RI.branch("1");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_1 = id_RI_DH.branch("1");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_224 = id_RI_DH.branch("2");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_256 = id_RI_DH.branch("3");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_384 = id_RI_DH.branch("4");
	public static final ASN1ObjectIdentifier id_RI_DH_SHA_512 = id_RI_DH.branch("5");

	public static final ASN1ObjectIdentifier id_RI_ECDH = id_RI.branch("2");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_1 = id_RI_ECDH.branch("1");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_224 = id_RI_ECDH.branch("2");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_256 = id_RI_ECDH.branch("3");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_384 = id_RI_ECDH.branch("4");
	public static final ASN1ObjectIdentifier id_RI_ECDH_SHA_512 = id_RI_ECDH.branch("5");

	// CardInfoLocator
	public static final ASN1ObjectIdentifier CI = smartcard.branch("6");

	// eIDSecurityInfo
	public static final ASN1ObjectIdentifier eIDSecurity = smartcard.branch("7");

	// PrivilegedTerminalInfo
	public static final ASN1ObjectIdentifier PT = smartcard.branch("8");
	
	// ECKA-EG
	public static final ASN1ObjectIdentifier ECKA_EG = smartcard.branch("9");
	public static final ASN1ObjectIdentifier ECKA_EG_REC = ECKA_EG.branch("1");
	public static final ASN1ObjectIdentifier ECKA_EG_REC_woKDF = ECKA_EG_REC.branch("1");
	public static final ASN1ObjectIdentifier ECKA_EG_INI = ECKA_EG.branch("2");
	public static final ASN1ObjectIdentifier ECKA_EG_INI_woKDF = ECKA_EG_INI.branch("1");
	
	// ECKA-DH
	public static final ASN1ObjectIdentifier ECKA_DH = smartcard.branch("10");
	public static final ASN1ObjectIdentifier ECKA_DH_woKDF = ECKA_DH.branch("1");
	
	// PS
	public static final ASN1ObjectIdentifier PS = smartcard.branch("11");
	
	public static final ASN1ObjectIdentifier PSA = PS.branch("1");
	public static final ASN1ObjectIdentifier PSA_DH_Schnorr = PSA.branch("1");
	public static final ASN1ObjectIdentifier PSA_DH_Schnorr_SHA224 = PSA_DH_Schnorr.branch("2");
	public static final ASN1ObjectIdentifier PSA_DH_Schnorr_SHA256 = PSA_DH_Schnorr.branch("3");
	public static final ASN1ObjectIdentifier PSA_DH_Schnorr_SHA384 = PSA_DH_Schnorr.branch("4");
	public static final ASN1ObjectIdentifier PSA_DH_Schnorr_SHA512 = PSA_DH_Schnorr.branch("5");
	public static final ASN1ObjectIdentifier PSA_ECDH_ECSchnorr = PSA.branch("2");
	public static final ASN1ObjectIdentifier PSA_ECDH_ECSchnorr_SHA224 = PSA_ECDH_ECSchnorr.branch("2");
	public static final ASN1ObjectIdentifier PSA_ECDH_ECSchnorr_SHA256 = PSA_ECDH_ECSchnorr.branch("3");
	public static final ASN1ObjectIdentifier PSA_ECDH_ECSchnorr_SHA384 = PSA_ECDH_ECSchnorr.branch("4");
	public static final ASN1ObjectIdentifier PSA_ECDH_ECSchnorr_SHA512 = PSA_ECDH_ECSchnorr.branch("5");
	public static final ASN1ObjectIdentifier PSM = PS.branch("2");
	public static final ASN1ObjectIdentifier PSM_DH_Schnorr = PSM.branch("1");
	public static final ASN1ObjectIdentifier PSM_DH_Schnorr_SHA224 = PSM_DH_Schnorr.branch("2");
	public static final ASN1ObjectIdentifier PSM_DH_Schnorr_SHA256 = PSM_DH_Schnorr.branch("3");
	public static final ASN1ObjectIdentifier PSM_DH_Schnorr_SHA384 = PSM_DH_Schnorr.branch("4");
	public static final ASN1ObjectIdentifier PSM_DH_Schnorr_SHA512 = PSM_DH_Schnorr.branch("5");
	public static final ASN1ObjectIdentifier PSM_ECDH_ECSchnorr = PSM.branch("2");
	public static final ASN1ObjectIdentifier PSM_ECDH_ECSchnorr_SHA224 = PSM_ECDH_ECSchnorr.branch("2");
	public static final ASN1ObjectIdentifier PSM_ECDH_ECSchnorr_SHA256 = PSM_ECDH_ECSchnorr.branch("3");
	public static final ASN1ObjectIdentifier PSM_ECDH_ECSchnorr_SHA384 = PSM_ECDH_ECSchnorr.branch("4");
	public static final ASN1ObjectIdentifier PSM_ECDH_ECSchnorr_SHA512 = PSM_ECDH_ECSchnorr.branch("5");
	public static final ASN1ObjectIdentifier PSC = PS.branch("3");
	public static final ASN1ObjectIdentifier PSC_DH_Schnorr = PSC.branch("1");
	public static final ASN1ObjectIdentifier PSC_DH_Schnorr_SHA224 = PSC_DH_Schnorr.branch("2");
	public static final ASN1ObjectIdentifier PSC_DH_Schnorr_SHA256 = PSC_DH_Schnorr.branch("3");
	public static final ASN1ObjectIdentifier PSC_DH_Schnorr_SHA384 = PSC_DH_Schnorr.branch("4");
	public static final ASN1ObjectIdentifier PSC_DH_Schnorr_SHA512 = PSC_DH_Schnorr.branch("5");
	public static final ASN1ObjectIdentifier PSC_ECDH_ECSchnorr = PSC.branch("2");
	public static final ASN1ObjectIdentifier PSC_ECDH_ECSchnorr_SHA224 = PSC_ECDH_ECSchnorr.branch("2");
	public static final ASN1ObjectIdentifier PSC_ECDH_ECSchnorr_SHA256 = PSC_ECDH_ECSchnorr.branch("3");
	public static final ASN1ObjectIdentifier PSC_ECDH_ECSchnorr_SHA384 = PSC_ECDH_ECSchnorr.branch("4");
	public static final ASN1ObjectIdentifier PSC_ECDH_ECSchnorr_SHA512 = PSC_ECDH_ECSchnorr.branch("5");
		
	// PCD Reader
	public static final ASN1ObjectIdentifier PCD = protocols.branch("3");
	
	// id_PACE PCD
	public static final ASN1ObjectIdentifier PACE_PCD = PCD.branch("4");

	public static final ASN1ObjectIdentifier PACE_PCD_DH_GM = PACE_PCD.branch("1");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_GM_3DES_CBC_CBC = PACE_PCD_DH_GM.branch("1");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_GM_AES_CBC_CMAC_128 = PACE_PCD_DH_GM.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_GM_AES_CBC_CMAC_192 = PACE_PCD_DH_GM.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_GM_AES_CBC_CMAC_256 = PACE_PCD_DH_GM.branch("4");

	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_GM = PACE_PCD.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_GM_3DES_CBC_CBC = PACE_PCD_ECDH_GM.branch("1");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_GM_AES_CBC_CMAC_128 = PACE_PCD_ECDH_GM.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_GM_AES_CBC_CMAC_192 = PACE_PCD_ECDH_GM.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_GM_AES_CBC_CMAC_256 = PACE_PCD_ECDH_GM.branch("4");

	public static final ASN1ObjectIdentifier PACE_PCD_DH_IM = PACE_PCD.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_IM_3DES_CBC_CBC = PACE_PCD_DH_IM.branch("1");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_IM_AES_CBC_CMAC_128 = PACE_PCD_DH_IM.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_IM_AES_CBC_CMAC_192 = PACE_PCD_DH_IM.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_DH_IM_AES_CBC_CMAC_256 = PACE_PCD_DH_IM.branch("4");

	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_IM = PACE_PCD.branch("4");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_IM_3DES_CBC_CBC = PACE_PCD_ECDH_IM.branch("1");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_IM_AES_CBC_CMAC_128 = PACE_PCD_ECDH_IM.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_IM_AES_CBC_CMAC_192 = PACE_PCD_ECDH_IM.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_IM_AES_CBC_CMAC_256 = PACE_PCD_ECDH_IM.branch("4");

	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_CAM = PACE_PCD.branch("6");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_CAM_AES_CBC_CMAC_128 = PACE_PCD_ECDH_IM.branch("2");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_CAM_AES_CBC_CMAC_192 = PACE_PCD_ECDH_IM.branch("3");
	public static final ASN1ObjectIdentifier PACE_PCD_ECDH_CAM_AES_CBC_CMAC_256 = PACE_PCD_ECDH_IM.branch("4");

	/** Applications **/
	public static final ASN1ObjectIdentifier applications = bsi_de.branch("3");
	
	// MRTD
	public static final ASN1ObjectIdentifier mrtd = applications.branch("1");

	public static final ASN1ObjectIdentifier policies = mrtd.branch("1");
	public static final ASN1ObjectIdentifier CSCA = policies.branch("1");
	public static final ASN1ObjectIdentifier CVCA = policies.branch("2");
	public static final ASN1ObjectIdentifier CVCA_ePassport = CVCA.branch("1");
	public static final ASN1ObjectIdentifier CVCA_eID = CVCA.branch("2");
	public static final ASN1ObjectIdentifier CVCA_eSign = CVCA.branch("3");
	public static final ASN1ObjectIdentifier DV =   policies.branch("3");
	public static final ASN1ObjectIdentifier DV_ePassport = DV.branch("1");
	public static final ASN1ObjectIdentifier DV_ePassport_bPol = DV_ePassport.branch("1");
	public static final ASN1ObjectIdentifier DV_eID = DV.branch("2");
	public static final ASN1ObjectIdentifier DV_eSign = DV.branch("3");

	public static final ASN1ObjectIdentifier roles = mrtd.branch("2");
	public static final ASN1ObjectIdentifier id_IS = roles.branch("1");
	public static final ASN1ObjectIdentifier id_AT = roles.branch("2");
	public static final ASN1ObjectIdentifier id_AT_eIDAccess = id_AT.branch("1");
	public static final ASN1ObjectIdentifier id_AT_specialFunctions = id_AT.branch("2");
	public static final ASN1ObjectIdentifier id_AT_eID_Biometrics = id_AT.branch("3");
	public static final ASN1ObjectIdentifier id_ST = roles.branch("3");
	
	public static final ASN1ObjectIdentifier extensions = mrtd.branch("3");
	public static final ASN1ObjectIdentifier description = extensions.branch("1");
	public static final ASN1ObjectIdentifier plainFormat = description.branch("1");
	public static final ASN1ObjectIdentifier htmlFormat = description.branch("2");
	public static final ASN1ObjectIdentifier pdfFormat = description.branch("3");
	public static final ASN1ObjectIdentifier sector = extensions.branch("2");
	public static final ASN1ObjectIdentifier PS_sector = extensions.branch("3");
	
	public static final ASN1ObjectIdentifier auxiliaryData = mrtd.branch("4");
	public static final ASN1ObjectIdentifier DateOfBirth = auxiliaryData.branch("1");
	public static final ASN1ObjectIdentifier DateOfExpiry = auxiliaryData.branch("2");
	public static final ASN1ObjectIdentifier CommunityID = auxiliaryData.branch("3");
	public static final ASN1ObjectIdentifier PSM_Message = auxiliaryData.branch("4");
	
	public static final ASN1ObjectIdentifier DefectList = mrtd.branch("5");
	public static final ASN1ObjectIdentifier AuthDefect = DefectList.branch("1");
	public static final ASN1ObjectIdentifier certRevoked = AuthDefect.branch("1");
	public static final ASN1ObjectIdentifier certReplaced = AuthDefect.branch("2");
	public static final ASN1ObjectIdentifier certChipAuthKeyRevoked = AuthDefect.branch("3");
	public static final ASN1ObjectIdentifier certActiveAuthKeyRevoked = AuthDefect.branch("4");
	public static final ASN1ObjectIdentifier ePassportDefect = DefectList.branch("2");
	public static final ASN1ObjectIdentifier ePassportDGMalformed = ePassportDefect.branch("1");
	public static final ASN1ObjectIdentifier SODInvalid = ePassportDefect.branch("2");
	public static final ASN1ObjectIdentifier COMSODDiscrepancy = ePassportDefect.branch("3");
	public static final ASN1ObjectIdentifier eIDDefect = DefectList.branch("3");
	public static final ASN1ObjectIdentifier eIDDGMalformed = eIDDefect.branch("1");
	public static final ASN1ObjectIdentifier eIDIntegrity = eIDDefect.branch("2");
	public static final ASN1ObjectIdentifier eIDSecurityInfoMissing = eIDDefect.branch("3");
	public static final ASN1ObjectIdentifier eIDDGMissing = eIDDefect.branch("4");
	public static final ASN1ObjectIdentifier DocumentDefect = DefectList.branch("4");
	public static final ASN1ObjectIdentifier CardSecurityMalformed = DocumentDefect.branch("1");
	public static final ASN1ObjectIdentifier ChipSecurityMalformed = DocumentDefect.branch("2");
	public static final ASN1ObjectIdentifier PowerDownReq = DocumentDefect.branch("3");
	public static final ASN1ObjectIdentifier DSMalformed = DocumentDefect.branch("4");
	public static final ASN1ObjectIdentifier EAC2PrivilegedTerminalInfoMissing = DocumentDefect.branch("5");

	// eID
	public static final ASN1ObjectIdentifier eID = applications.branch("2");
	public static final ASN1ObjectIdentifier SecurityObject = eID.branch("1");
	public static final ASN1ObjectIdentifier BlackList = eID.branch("2");
	
	// eCard-API
	public static final ASN1ObjectIdentifier eCardAPI = applications.branch("3");
		
	// SMGW
	public static final ASN1ObjectIdentifier SMGW = applications.branch("4");

	// digital Seal
	public static final ASN1ObjectIdentifier digitalSeal = applications.branch("4");
	

	/** PKI **/
	public static final ASN1ObjectIdentifier pki = bsi_de.branch("4");
	public static final ASN1ObjectIdentifier x509 = pki.branch("1");
	public static final ASN1ObjectIdentifier certRequest = x509.branch("1");
	public static final ASN1ObjectIdentifier rfc4211_CertReqMsgs = certRequest.branch("1");
}
