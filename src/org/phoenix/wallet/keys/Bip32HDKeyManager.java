package org.phoenix.wallet.keys;

import java.util.LinkedList;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.phoenix.passwords.PasswordFailException;
import org.phoenix.random.Random;





import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.KeyCrypterScrypt;



public class Bip32HDKeyManager extends KeyManagerAbstract implements HDKeyManager{
	TreeMap<int[], EncryptedDeterministicKey> keys = new TreeMap<int[], EncryptedDeterministicKey>();
	
	public Bip32HDKeyManager() {
		keys.put(new int[]{}, new EncryptedDeterministicKey(HDKeyDerivation.createMasterPrivateKey(Random.get_bytes(16))));
		set_has_private_keys(true);
		set_password_protected(false);
	}
	
	public Bip32HDKeyManager(HDECPublicKey k) {
		keys.put(new int[]{}, new EncryptedDeterministicKey(KeyTransformer.make_DeterministicKey(k)));
		set_has_private_keys(false);
		set_password_protected(false);
	}
	
	public Bip32HDKeyManager(HDECKeypair k) {
		keys.put(new int[]{}, new EncryptedDeterministicKey(KeyTransformer.make_DeterministicKey(k)));
		set_has_private_keys(true);
		if(k.password_protected()) {
			set_crypter(new KeyCrypterScrypt());
			set_password_protected(true);
		} else {
			set_password_protected(false);
		}
	}

	@Override
	public HDKeyManager export_HDManager(int[] n) {
		return new Bip32HDKeyManager((HDECPublicKey) keys.get(n).export_HDPublicKey());
	}

	@Override
	public HDKeyManager export_private_HDManager(int[] n) throws PasswordFailException {
		return new Bip32HDKeyManager((HDECKeypair) keys.get(n).export_HDPrivateKey());
	}

	@Override
	public Iterable<PublicKey> get_keys() {
		LinkedList<PublicKey> keys = new LinkedList<PublicKey>();
		for(Entry<int[], EncryptedDeterministicKey> map : this.keys.entrySet()) {
			keys.add(new ECPublicKey(map.getValue()));
		}
		return keys;
	}

	@Override
	public PublicKey get_PublicKey(int[] n) {
		return keys.get(n).get_PublicKey();
	}

	@Override
	public Keypair get_PrivateKey(int[] n) throws PasswordFailException {
		return keys.get(n).export_PrivateKey();
	}

	@Override
	protected void recrypt(String pw) throws PasswordFailException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void encrypt(String pw) {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void decrypt() throws PasswordFailException {
		// TODO Auto-generated method stub
		
	}
}
