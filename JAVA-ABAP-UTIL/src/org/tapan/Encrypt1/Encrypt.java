package org.tapan.Encrypt1;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class Encrypt {

	public static String encryptAsymmetricKey(String pubkey, String password) throws Exception {
		PublicKey publicKeys = convertPubStringToKey(pubkey);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		cipher.init(Cipher.ENCRYPT_MODE, publicKeys);
		byte[] encryptedText = cipher.doFinal(password.getBytes());
		String encryptedPassword = Base64.getEncoder().encodeToString(encryptedText);
		return encryptedPassword;
	}

	private static PublicKey convertPubStringToKey(String publikkey) {
		PublicKey pubKey = null;
		byte[] publicBytes = Base64.getDecoder().decode(publikkey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pubKey;
	}
	/*
	 * public static String encryptAsymmetricKey(String pubkey, byte[] appKey)
	 * throws Exception { PublicKey publicKeys = convertPubStringToKey(pubkey);
	 * Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
	 * cipher.init(Cipher.ENCRYPT_MODE, publicKeys); byte[] encryptedText =
	 * cipher.doFinal(appKey); String encryptedAppKey =
	 * Base64.getEncoder().encodeToString(encryptedText); return encryptedAppKey; }
	 */
	
}
