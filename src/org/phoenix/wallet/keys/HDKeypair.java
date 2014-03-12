package org.phoenix.wallet.keys;

import org.phoenix.passwords.PasswordFailException;

public interface HDKeypair extends HDPublicKey, Keypair {
	
	public HDKeypair private_child(int n);
	
	//It may be necessary to give a password in order to generate the private key. 
	//Therefore this always exports a private key that is unencrypted. 
	public Keypair export_PrivateKey() throws PasswordFailException;
	public HDKeypair export_HDPrivateKey() throws PasswordFailException;
}
