package org.phoenix.wallet.keys;


import org.phoenix.passwords.PasswordFailException;

public interface HDKeyManager extends KeyManager{
	public PublicKey get_PublicKey(int[] n);
	public Keypair get_PrivateKey(int[] n) throws PasswordFailException;
	public HDKeyManager export_HDManager(int[] n);
	public HDKeyManager export_private_HDManager(int[] n) throws PasswordFailException;
}
