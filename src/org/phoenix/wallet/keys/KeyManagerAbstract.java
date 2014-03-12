package org.phoenix.wallet.keys;

import java.security.SignatureException;

import org.phoenix.passwords.PasswordFailException;
import org.phoenix.passwords.Passwords;
import org.phoenix.random.Random;
import org.phoenix.wallet.Pair;
import org.spongycastle.crypto.params.KeyParameter;





import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.EncryptedPrivateKey;
import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.KeyCrypter;
import com.google.bitcoin.crypto.KeyCrypterScrypt;


public abstract class KeyManagerAbstract implements KeyManager{
	private boolean has_private_keys;
	private boolean password_protected;
	private KeyCrypter crypter = null;

	@Override
	public boolean has_private_keys() {
		return has_private_keys;
	}

	@Override
	public boolean password_protected() {
		return password_protected;
	}
	
	protected void set_has_private_keys(boolean b) {
		has_private_keys = b;
	}
	
	protected void set_password_protected(boolean b) {
		password_protected = b;
	}
	
	public KeyCrypter get_crypter() {
		return crypter;
	}

	public void set_crypter(KeyCrypter crypter) {
		this.crypter = crypter;
	}
	
	@Override
	public final void set_password(String pw) throws PasswordFailException {
		if(!has_private_keys) return;
		if(password_protected) {
			recrypt(pw);
		} else {
			crypter = new KeyCrypterScrypt();
			has_private_keys = true;
			password_protected = true;
			encrypt(pw);
		}
	}
	
	@Override
	public final void unset_password() throws PasswordFailException {
		if(!has_private_keys) return;
		if(password_protected) {
			decrypt();
			has_private_keys = false;
			password_protected = false;
		} 
	}
	
	protected abstract void recrypt(String pw) throws PasswordFailException;
	
	protected abstract void encrypt(String pw);
	
	protected abstract void decrypt() throws PasswordFailException;

	//This class is not guaranteed to contain the private keys or to be encrypted. 
	protected class EncryptedDeterministicKey implements HDKeypair {
		private DeterministicKey key;
		private EncryptedPrivateKey crypt = null;
		boolean has_private_keys;
		boolean password_protected;
		EncryptedDeterministicKey parent = null;
		
		//Generate randomly. 
		public EncryptedDeterministicKey() {
			has_private_keys = true;
			password_protected = false;
			parent = null;
			key = HDKeyDerivation.createMasterPrivateKey(Random.get_bytes(16));
		}
		
		public EncryptedDeterministicKey(DeterministicKey k) {
			password_protected = false;
			has_private_keys = key.hasPrivate();
			key = KeyTransformer.clone_without_memory(k);
		}
		
		public EncryptedDeterministicKey(HDPublicKey k) {
			key = KeyTransformer.make_DeterministicKey(k);
			has_private_keys = false;
			password_protected = false;
		}
		
		private EncryptedDeterministicKey(DeterministicKey k, boolean has_private, boolean pp, EncryptedDeterministicKey par) {
			parent = par;
			key = k;
			password_protected = pp;
			has_private_keys = has_private;
		}
		
		Pair<byte[], String> gen_private(int child) throws PasswordFailException{
			if(!password_protected) return null;
			Pair<byte[], String> pass;
			if(crypt == null) {
				if(parent == null) return null;
				pass = parent.gen_private(key.getChildNumber().getChildNumber());
			} else {
				pass = Passwords.check_passwords(crypt, crypter);
			}
			return new Pair<byte[], String>(HDKeyDerivation.deriveChildKey(HDKeyDerivation.createMasterPrivKeyFromBytes(pass.fst(), key.getChainCode()), child).getPrivKeyBytes(), pass.snd());
		}

		private byte[] check_password() throws PasswordFailException {
			if(!password_protected) return null;
			if(crypt == null) {
				if(parent == null) return null;
				Pair<byte[], String> pass = gen_private(key.getChildNumber().getChildNumber());
				crypt = crypter.encrypt(pass.fst(), crypter.deriveKey(pass.snd())); 
				return pass.fst();
			} else {
				return Passwords.check_passwords(crypt, crypter).fst();
			}
		}
		
		@Override
		public boolean verify_signature(String doc, String sig) {
			try {
				key.toECKey().verifyMessage(doc, sig);
			} catch (SignatureException e) {
				return false;
			}
			return true;
		}
		
		@Override
		public boolean password_protected() {
			return password_protected;
		}
		
		public boolean has_private_key() {
			return has_private_keys;
		}
		
		@Override
		public String sign(String s) throws PasswordFailException {
			if(!has_private_keys) return null;
			if(password_protected) {
				byte[] privkey = check_password();
				if (privkey == null) throw new PasswordFailException();
				return (new ECKeypair(key.getPubKeyBytes(), privkey)).sign(s);
			} else if(key.hasPrivate()){
				return key.toECKey().signMessage(s);
			} else return null; //Line should never happen. 
		}
		
		@Override
		public PublicKey get_PublicKey() {
			return new ECPublicKey(key);
		}
		
		@Override
		public boolean set_password(String pw) throws PasswordFailException {
			byte[] privkey;
			if(crypt != null) {
				privkey = check_password();
				if(privkey == null) throw new PasswordFailException();
			} else if(key.hasPrivate()) {
				privkey = key.getPrivKeyBytes();
				key = key.getPubOnly();
			} else return false;
			
			crypter = new KeyCrypterScrypt();
			KeyParameter param = crypter.deriveKey(pw);
			crypt = crypter.encrypt(privkey, param);
			return true;
		}
		
		public EncryptedDeterministicKey child(int n) {
			if(n < 0) return null;
			return new EncryptedDeterministicKey(HDKeyDerivation.deriveChildKey(key, n), has_private_keys, password_protected, this);
		}

		@Override
		public HDPublicKey public_child(int n) {
			if(n < 0) return null;
			return new HDECPublicKey(HDKeyDerivation.deriveChildKey(key, n));
		}

		@Override
		public HDKeypair private_child(int n) {
			if(n < 0) return null;
			return HDECKeypair.construct_private_key(HDKeyDerivation.deriveChildKey(key, n));
		}

		@Override
		public Keypair export_PrivateKey() throws PasswordFailException {
			if(!has_private_keys) return null;
			if(password_protected) {
				byte[] privkey;
				privkey = check_password();
				return new ECKeypair(key.getPubKeyBytes(), privkey);
			} else return ECKeypair.construct_private_key(key);
		}

		@Override
		public HDPublicKey export_HDPublicKey() {
			if(key.hasPrivate()) {
				return new HDECPublicKey(KeyTransformer.clone_without_memory(key.getPubOnly()));
			} else {
				return new HDECPublicKey(KeyTransformer.clone_without_memory(key));
			}
		}

		@Override
		public HDKeypair export_HDPrivateKey() throws PasswordFailException {
			if(!has_private_keys) return null;
			if(password_protected) {
				byte[] privkey;
				privkey = check_password();
				return new HDECKeypair(privkey, key.getChainCode());
			} else {
				return HDECKeypair.construct_private_key(KeyTransformer.clone_without_memory(key));
			}
		}

		@Override
		//This function won't work because it would have to recurse back to the
		//master key and then be applied to all the children, and but this object
		//doesn't know who its children are. 
		public void unset_password() throws PasswordFailException {
			return;
		}

		@Override
		public ECKey to_ECKey() {
			if(crypt == null) return key.toECKey();
			else return new ECKey(crypt, key.toECKey().getPubKey(), crypter);
		}
	}
}
