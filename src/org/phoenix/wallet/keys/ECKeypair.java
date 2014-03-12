package org.phoenix.wallet.keys;

import org.phoenix.passwords.PasswordFailException;
import org.phoenix.passwords.Passwords;
import org.spongycastle.crypto.params.KeyParameter;



import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.EncryptedPrivateKey;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterScrypt;


public class ECKeypair extends ECPublicKey implements Keypair{

	//Generate randomly 
	public ECKeypair() {
		key = new ECKey();
	}
	
	//If this key is encrypted, 
	public ECKeypair(Keypair k) {
		key = KeyTransformer.make_ECKey(k);
	}

	public ECKeypair(byte[] pubKeyBytes, EncryptedPrivateKey crypt) {
		KeyCrypter crypter = null; 
		key = new ECKey(crypt, pubKeyBytes, crypter);
	}
	
	public ECKeypair(byte[] pubKeyBytes, byte[] privKeyBytes) {
		key = new ECKey(privKeyBytes, pubKeyBytes);
	}
	
	//This function assumes that key has the private key, which is why it is private. 
	private ECKeypair(ECKey k) {
		key = k;
	}

	@Override
	public boolean password_protected() {
		return key.isEncrypted();
	}

	@Override
	public String sign(String s) {
		return key.signMessage(s);
	}
	
	public ECKey to_ECKey() {
		return key;
	}
	
	private byte[] check_password() throws PasswordFailException{
		return Passwords.check_passwords(key.getEncryptedPrivateKey(), key.getKeyCrypter()).fst();
	}

	@Override
	public boolean set_password(String pw) throws PasswordFailException {
		byte[] privkey;
		if(key.isEncrypted()) {
			privkey = check_password();
		} else {
			privkey = key.getPrivKeyBytes();
		}
		KeyCrypter crypter = new KeyCrypterScrypt();
		KeyParameter param = crypter.deriveKey(pw);
		EncryptedPrivateKey encrypted = crypter.encrypt(privkey, param);
		
		key = new ECKey(encrypted, key.getPubKey(), crypter);
		
		return true;
	}
	
	static public ECKeypair construct_private_key(DeterministicKey key) {
		if(key.hasPrivate()) {
			return new ECKeypair(key.toECKey());
		} else return null;
	}

	@Override
	public void unset_password() throws PasswordFailException {
		if(key.isEncrypted()) {
			byte[] privkey;
			privkey = check_password();
			key = new ECKey(privkey, key.getPubKey());
		}
	}
	
	static public ECKeypair construct_private_key(ECKey key) {
		if(key.hasPrivKey()) {
			return new ECKeypair(key);
		} else return null;
	}
}
