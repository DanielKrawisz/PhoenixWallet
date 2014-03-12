package org.phoenix.passwords;

import java.util.LinkedList;

import org.phoenix.wallet.Pair;


import com.google.bitcoin.crypto.EncryptedPrivateKey;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterException;

//The password manager. 
public class Passwords {
	private Passwords() { }
		
	private static LinkedList<String> passwords;
	
	public static Pair<byte[], String> check_passwords(EncryptedPrivateKey priv, KeyCrypter crypter) throws PasswordFailException{
		for(String password : passwords) {
			try {
				return new Pair<byte[], String>(crypter.decrypt(priv, crypter.deriveKey(password)), password);
			} catch (KeyCrypterException x) {
				continue;
			}
		}
		throw new PasswordFailException();
	}
}
