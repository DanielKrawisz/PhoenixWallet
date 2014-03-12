package org.phoenix.wallet.keys;

import java.util.LinkedList;

import org.phoenix.passwords.PasswordFailException;






//A public linear key generator that only remembers one key at a time. 
public class Bip32SequentialKeyManager extends KeyManagerAbstract implements SequentialKeyManager{
	private HDPublicKey hdkey;
	
	//Generate from a public HD key. 
	public Bip32SequentialKeyManager(HDPublicKey hdk) {
		hdkey = hdk;
	}

	@Override
	public boolean has_private_keys() {
		return false;
	}

	@Override
	public boolean password_protected() {
		return false;
	}

	@Override
	public Iterable<PublicKey> get_keys() {
		LinkedList<PublicKey> keys = new LinkedList<PublicKey>();
		keys.addFirst(hdkey.get_PublicKey());
		return keys;
	}
	
	@Override
	public PublicKey latest() {
		return hdkey.get_PublicKey();
	}

	@Override
	public void generate_next() {
		hdkey = hdkey.public_child(0);
	}

	@Override
	public SequentialKeyManager export_SequentialKeyManager() {
		return new Bip32SequentialKeyManager(hdkey);
	}

	@Override
	protected void recrypt(String pw) throws PasswordFailException {}

	@Override
	protected void encrypt(String pw) {}

	@Override
	protected void decrypt() {}

}
