package org.phoenix.wallet.keys;

public interface HDPublicKey extends PublicKey{
	
	public HDPublicKey public_child(int n);
	
	public HDPublicKey export_HDPublicKey();
	
	public PublicKey get_PublicKey();
}
