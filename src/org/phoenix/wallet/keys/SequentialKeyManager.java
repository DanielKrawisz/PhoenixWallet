package org.phoenix.wallet.keys;

//This key manager contains only a single public key at a time. 
//It can be used to generate payment addresses without granting
//the ability to know the total balance. 
public interface SequentialKeyManager extends KeyManager{
	public PublicKey latest();
	public void generate_next();
	public SequentialKeyManager export_SequentialKeyManager();
}
