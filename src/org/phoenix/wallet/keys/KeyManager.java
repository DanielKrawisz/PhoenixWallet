package org.phoenix.wallet.keys;


import org.phoenix.passwords.PasswordFailException;

public interface KeyManager {
	public boolean has_private_keys(); //Whether the private keys are included. 
	public boolean password_protected(); //Whether the private keys are password protected.
	public Iterable<PublicKey> get_keys(); //The Bitcoin public keys. 
	public void set_password(String pw) throws PasswordFailException;
	public void unset_password() throws PasswordFailException;
}
