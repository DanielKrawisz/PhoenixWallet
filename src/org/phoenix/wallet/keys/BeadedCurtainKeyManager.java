package org.phoenix.wallet.keys;


import org.phoenix.passwords.PasswordFailException;

public interface BeadedCurtainKeyManager extends KeyManager{
	public PublicKey get_PublicKey(int n, int m);
	public Keypair get_PrivateKey(int n, int m) throws PasswordFailException;
	public BeadedCurtainKeyManager export_BeadedCurtainManager();
	public BeadedCurtainKeyManager export_private_BeadedCurtainManager() throws PasswordFailException;
	public LinearKeyManager export_LinearKeyManager();
	public LinearKeyManager export_private_LinearKeyManager() throws PasswordFailException;
	public LinearKeyManager export_LinearKeyManager(int n);
	public LinearKeyManager export_private_LinearKeyManager(int n) throws PasswordFailException;
	public int length();
	public int chain_length(int n);
	public SequentialKeyManager export_SequentialKeyManager(int n, int m);
}
