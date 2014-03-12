package org.phoenix.wallet.keys;


import org.phoenix.passwords.PasswordFailException;

public interface LinearKeyManager extends SequentialKeyManager{
	public PublicKey get_PublicKey(int n); 
	public Keypair get_PrivateKey(int n) throws PasswordFailException; 
	public LinearKeyManager export_LinearKeyManager(int n); 
}
