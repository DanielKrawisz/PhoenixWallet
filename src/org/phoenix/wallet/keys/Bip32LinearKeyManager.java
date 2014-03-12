package org.phoenix.wallet.keys;

import java.util.ArrayList;
import java.util.LinkedList;

import org.phoenix.passwords.PasswordFailException;

import com.google.bitcoin.crypto.DeterministicKey;

public class Bip32LinearKeyManager extends KeyManagerAbstract implements LinearKeyManager{
	private ArrayList<EncryptedDeterministicKey> hdkey;
	
	//Start randomly.
	public Bip32LinearKeyManager() {
		hdkey = new ArrayList<EncryptedDeterministicKey>(100);
		hdkey.add(new EncryptedDeterministicKey());
		set_has_private_keys(true);
		set_password_protected(false);
	}
	
	//Start from a deterministic key. 
	public Bip32LinearKeyManager(DeterministicKey key) {
		hdkey = new ArrayList<EncryptedDeterministicKey>(100);
		if(key.hasPrivate()) {
			set_has_private_keys(true);
			hdkey.add(new EncryptedDeterministicKey(key));
		} else {
			set_has_private_keys(false);
			hdkey.add(new EncryptedDeterministicKey(key));
		}
		set_password_protected(false);
	}
	
	public Bip32LinearKeyManager(HDKeypair key) {
		hdkey = new ArrayList<EncryptedDeterministicKey>(100);
		set_has_private_keys(true);
		hdkey.add(new EncryptedDeterministicKey(key));
		set_password_protected(false);
	}
	
	public Bip32LinearKeyManager(HDPublicKey key) {
		hdkey = new ArrayList<EncryptedDeterministicKey>(100);
		set_has_private_keys(false);
		hdkey.add(new EncryptedDeterministicKey(key));
		set_password_protected(false);
	}

	@Override
	public PublicKey latest() {
		return new ECPublicKey(hdkey.get(hdkey.size()-1));
	}

	@Override
	public Iterable<PublicKey> get_keys() {
		LinkedList<PublicKey> list = new LinkedList<PublicKey>();
		for(EncryptedDeterministicKey key : hdkey) {
			list.add(new ECPublicKey(key));
		}
		return list;
	}

	@Override
	public void generate_next() {
		hdkey.add(hdkey.get(hdkey.size()-1).child(0));
	}

	@Override
	public SequentialKeyManager export_SequentialKeyManager() {
		return new Bip32SequentialKeyManager(hdkey.get(hdkey.size()-1));
	}
	
	@Override
	public PublicKey get_PublicKey(int n) {
		if(n < 0) return null;
		while(n >= hdkey.size()) generate_next();
		return hdkey.get(n).get_PublicKey();
	}

	@Override
	public Keypair get_PrivateKey(int n) throws PasswordFailException {
		if(n < 0) return null;
		while(n >= hdkey.size()) generate_next();
		return hdkey.get(n).export_PrivateKey();
	}

	@Override
	public LinearKeyManager export_LinearKeyManager(int n) {
		if(n < 0) return null;
		while(n >= hdkey.size()) generate_next();
		return new Bip32LinearKeyManager(hdkey.get(n));
	}

	@Override
	protected void recrypt(String pw) throws PasswordFailException {
		for(EncryptedDeterministicKey key : hdkey) {
			if(!key.set_password(pw)) return;
		}
	}

	@Override
	protected void encrypt(String pw) {
		for(EncryptedDeterministicKey key : hdkey) {
			try {
				if(!key.set_password(pw)) return;
			} catch (PasswordFailException e) {
				return; //Shouldn't happen. 
			}
		}
	}

	@Override
	protected void decrypt() throws PasswordFailException {
		for(EncryptedDeterministicKey key : hdkey) {
			key.unset_password();
		}
	}
}
