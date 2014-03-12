package org.phoenix.wallet.keys;

import org.phoenix.passwords.PasswordFailException;
import org.phoenix.passwords.Passwords;
import org.phoenix.random.Random;


import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.EncryptedPrivateKey;
import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterScrypt;


public class HDECKeypair extends HDECPublicKey implements HDKeypair{
	EncryptedPrivateKey crypt;
	KeyCrypter crypter;
	
	//Generate randomly 
	public HDECKeypair() {
		crypt = null;
		crypter = null;
		key = HDKeyDerivation.createMasterPrivateKey(Random.get_bytes(16));
	}
	
	//This has to assume that the private key is included. 
	private HDECKeypair(DeterministicKey k) {
		key = k;
		crypt = null;
		crypter = null;
	}
	
	public HDECKeypair(HDKeypair k) throws PasswordFailException {
		crypt = null;
		key = KeyTransformer.make_DeterministicKey(k.export_HDPrivateKey());
	}
	
	public HDECKeypair(byte[] privkey, byte[] chaincode) {
		crypt = null;
		key = HDKeyDerivation.createMasterPrivKeyFromBytes(privkey, chaincode); 
	}
	
	public Keypair export_PrivateKey() {
		return ECKeypair.construct_private_key(key.toECKey());
	}
	
	public HDPublicKey get_HDPublicKey() {
		return new HDECPublicKey(key.getPubOnly());
	}
	
	public HDKeypair private_child(int n) {
		if(n < 0) return null;
		return new HDECKeypair(HDKeyDerivation.deriveChildKey(key, n));
	}
	
	private byte[] check_password() throws PasswordFailException {
		return Passwords.check_passwords(key.toECKey().getEncryptedPrivateKey(), key.toECKey().getKeyCrypter()).fst();
	}

	@Override
	public HDPublicKey public_child(int n) {
		if(n < 0) return null;
		return new HDECPublicKey(HDKeyDerivation.deriveChildKey(key.getPubOnly(), n));
	}

	@Override
	public boolean password_protected() {
		return crypt != null;
	}

	@Override
	public String sign(String s) {
		return key.toECKey().signMessage(s);
	}

	@Override
	public PublicKey get_PublicKey() {
		return new ECPublicKey(key.getPubOnly().toECKey());
	}

	@Override
	public boolean set_password(String pw) throws PasswordFailException {
		byte[] privkey;
		if(crypt == null) {
			privkey = check_password();
			if (privkey == null) throw new PasswordFailException();
		} else {
			privkey = key.getPrivKeyBytes();
			key = key.getPubOnly(); 
		}
		crypter = new KeyCrypterScrypt();
		crypt = crypter.encrypt(privkey, crypter.deriveKey(pw));
		return true;
	}

	@Override
	public HDPublicKey export_HDPublicKey() {
		return new HDECPublicKey(key.getPubOnly());
	}

	@Override
	public HDKeypair export_HDPrivateKey() throws PasswordFailException {
		if(crypt == null) {
			return new HDECKeypair(key);
		} else {
			byte[] privkey = check_password();
			return new HDECKeypair(key.getPrivKeyBytes(), privkey);
		}
	}

	@Override
	public void unset_password() throws PasswordFailException {
		byte[] privkey;
		if(crypt == null) return;
		privkey = check_password();
		crypt = null;
		crypter = null;
		key = HDKeyDerivation.createMasterPrivKeyFromBytes(privkey, key.getChainCode());
	}

	@Override
	public ECKey to_ECKey() {
		if(crypt == null) return key.toECKey();
		else return new ECKey(crypt, key.toECKey().getPubKey(), crypter);
	}
	
	public static HDECKeypair construct_private_key(DeterministicKey k) {
		if(k.hasPrivate()) {
			return new HDECKeypair(k);
		} else return null;
	}
}
