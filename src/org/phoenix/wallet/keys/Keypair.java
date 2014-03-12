package org.phoenix.wallet.keys;

import org.phoenix.passwords.PasswordFailException;

public interface Keypair extends PublicKey {
	public boolean password_protected();
	public String sign(String s) throws PasswordFailException;
	public boolean set_password(String pw) throws PasswordFailException;
	public void unset_password() throws PasswordFailException;
}
