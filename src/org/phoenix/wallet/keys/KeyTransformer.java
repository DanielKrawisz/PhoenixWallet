package org.phoenix.wallet.keys;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.HDKeyDerivation;

//A set of functions for transforming different key classes into one another. 
class KeyTransformer {
	private KeyTransformer() {}
	
	static public DeterministicKey make_DeterministicKey(HDPublicKey key) {
		if(key instanceof HDECPublicKey) {
			return ((HDECPublicKey) key).key;
		} else return null;
	}
	
	//Remove parent and key number. 
	static public DeterministicKey clone_without_memory(DeterministicKey key) {
		return HDKeyDerivation.createMasterPrivKeyFromBytes(key.getPrivKeyBytes(), key.getChainCode()); 
	}

	public static ECKey make_ECKey(PublicKey k) {
		return duplicate(k.to_ECKey());
	}
	
	public static ECKey duplicate(ECKey k) {
		return new ECKey(k.getPrivKeyBytes(), k.getPubKey());
	}
}
