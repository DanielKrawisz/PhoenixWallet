package org.phoenix.wallet.keys;

import java.util.ArrayList;
import java.util.LinkedList;

import org.phoenix.passwords.PasswordFailException;




import com.google.bitcoin.crypto.DeterministicKey;



public class Bip32BeadedCurtainKeyManager extends KeyManagerAbstract implements BeadedCurtainKeyManager{
	ArrayList<ArrayList<EncryptedDeterministicKey>> bckey = new ArrayList<ArrayList<EncryptedDeterministicKey>>(100);
	
	//Start randomly.
	public Bip32BeadedCurtainKeyManager() {
		bckey = new ArrayList<ArrayList<EncryptedDeterministicKey>>(100);
		bckey.add(new ArrayList<EncryptedDeterministicKey>(100));
		set_has_private_keys(true);
		set_password_protected(false);
		generate_next(0);
	}
	
	//Start from a deterministic key. 
	public Bip32BeadedCurtainKeyManager(DeterministicKey key) {
		bckey = new ArrayList<ArrayList<EncryptedDeterministicKey>>(100);
		if(key.hasPrivate()) {
			set_has_private_keys(true);
			bckey.add(new ArrayList<EncryptedDeterministicKey>(100));
			bckey.get(0).add(new EncryptedDeterministicKey(key));
		} else {
			set_has_private_keys(false);
			bckey.add(new ArrayList<EncryptedDeterministicKey>(100));
			bckey.get(0).add(new EncryptedDeterministicKey(key));
		}
		set_password_protected(false);
		generate_next(0);
	}
	
	public Bip32BeadedCurtainKeyManager(HDKeypair key) {
		bckey = new ArrayList<ArrayList<EncryptedDeterministicKey>>(100);
		set_has_private_keys(true);
		bckey.add(new ArrayList<EncryptedDeterministicKey>(100));
		bckey.get(0).add(new EncryptedDeterministicKey(key));
		set_password_protected(false);
		generate_next(0);
	}
	
	public Bip32BeadedCurtainKeyManager(HDPublicKey key) {
		bckey = new ArrayList<ArrayList<EncryptedDeterministicKey>>(100);
		set_has_private_keys(false);
		bckey.add(new ArrayList<EncryptedDeterministicKey>(100));
		bckey.get(0).add(new EncryptedDeterministicKey(key));
		set_password_protected(false);
		generate_next(0);
	}

	private void generate_next_chain() {
		ArrayList<EncryptedDeterministicKey> key = new ArrayList<EncryptedDeterministicKey>(100);
		key.add(bckey.get(bckey.size()-1).get(0).child(1));
		key.add(key.get(0).child(0));
		bckey.add(key);
	}

	private void generate_next(int n) {
		if(n < 0) return;
		while(n >= bckey.size()) {
			generate_next_chain();
		}
		ArrayList<EncryptedDeterministicKey> key = bckey.get(n);
		key.add(key.get(key.size()-1).child(0));
	}

	@Override
	public int length() {
		return bckey.size();
	}

	@Override
	public int chain_length(int n) {
		if(n < 0) return -1;
		if(n >= bckey.size()) return 0;
		else return bckey.get(n).size();
	}

	@Override
	public BeadedCurtainKeyManager export_BeadedCurtainManager() {
		return new Bip32BeadedCurtainKeyManager(bckey.get(0).get(0).export_HDPublicKey());
	}

	@Override
	public BeadedCurtainKeyManager export_private_BeadedCurtainManager() {
		if(!has_private_keys()) return null;
		return new Bip32BeadedCurtainKeyManager(bckey.get(0).get(0).export_HDPublicKey());
	}

	@Override
	public LinearKeyManager export_LinearKeyManager(int n) {
		if(n < 0) return null;
		while(n >= bckey.size()) {
			generate_next_chain();
		}
		return new Bip32LinearKeyManager(bckey.get(n).get(1).export_HDPublicKey());
	}

	@Override
	public LinearKeyManager export_private_LinearKeyManager(int n) throws PasswordFailException {
		while(n >= bckey.size()) {
			generate_next_chain();
		}
		return new Bip32LinearKeyManager(bckey.get(n).get(1).export_HDPrivateKey());
	}

	@Override
	//Generates a new chain and exports it. 
	public LinearKeyManager export_LinearKeyManager() {
		generate_next_chain();
		return new Bip32LinearKeyManager(bckey.get(bckey.size() - 1).get(1).export_HDPublicKey());
	}

	@Override
	//Generates a new chain and exports it. 
	public LinearKeyManager export_private_LinearKeyManager() throws PasswordFailException {
		generate_next_chain();
		return new Bip32LinearKeyManager(bckey.get(bckey.size() - 1).get(1).export_HDPrivateKey());
	}

	@Override
	public SequentialKeyManager export_SequentialKeyManager(int n, int m) {
		if(n < 0 || m <= 0) return null; //Dangerous to export zeroth key, since it can generate other chains. 
		ArrayList<EncryptedDeterministicKey> chain = bckey.get(n); 
		return new Bip32SequentialKeyManager(chain.get(m));
	}

	@Override
	public PublicKey get_PublicKey(int n, int m) {
		return new ECPublicKey(bckey.get(n).get(m));
	}

	@Override
	public Keypair get_PrivateKey(int n, int m) throws PasswordFailException{
		return bckey.get(n).get(m).export_HDPrivateKey();
	}

	@Override
	public Iterable<PublicKey> get_keys() {
		LinkedList<PublicKey> keys = new LinkedList<PublicKey>();
		for(ArrayList<EncryptedDeterministicKey> chain : bckey) {
			for(EncryptedDeterministicKey key : chain) {
				keys.add(key);
			}
		}
		return keys;
	}

	@Override
	protected void recrypt(String pw) throws PasswordFailException {
		for(ArrayList<EncryptedDeterministicKey> list : bckey) {
			for(EncryptedDeterministicKey key : list) {
				if(!key.set_password(pw)) return;
			}
		}
	}

	@Override
	protected void encrypt(String pw) {
		for(ArrayList<EncryptedDeterministicKey> list : bckey) {
			for(EncryptedDeterministicKey key : list) {
				try {
					if(!key.set_password(pw)) return;
				} catch (PasswordFailException e) {
					return; //Shouldn't happen. 
				}
			}
		}
	}

	@Override
	protected void decrypt() throws PasswordFailException {
		for(ArrayList<EncryptedDeterministicKey> list : bckey) {
			for(EncryptedDeterministicKey key : list) {
				key.unset_password();
			}
		}
	}
}