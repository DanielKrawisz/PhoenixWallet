package org.phoenix.wallet.keys;

import com.google.bitcoin.core.ECKey;

public interface PublicKey {
	public boolean verify_signature(String doc, String sig);
	public ECKey to_ECKey();
}
