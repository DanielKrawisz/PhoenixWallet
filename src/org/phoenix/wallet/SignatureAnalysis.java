package org.phoenix.wallet;

import javax.net.ssl.KeyManager;


import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Transaction;

//Not sure if this will make it in the final version. 
public class SignatureAnalysis {
	public boolean can_make_valid; //The key manager can make the transaction valid. 
	public boolean can_sign; //The key manager has private keys that can sign the transaction. 
	public boolean could_sign; //The key manager has a public key such that the private key could sign the transaction but is missing. 
	public boolean could_make_valid; //There are public keys such that the private keys are missing, but if they were there they could make the transaction valid. 
	public Transaction t;
	public Iterable<Pair<KeyManager, Iterable<ECKey>>> keyManagers;
	
	public Transaction sign() {
		//TODO: Fill this in. 
		return null;
	}
}
