package org.phoenix.wallet.keys;

import static org.junit.Assert.*;

import org.junit.Test;

import com.google.bitcoin.core.ECKey;

public class ECKeypairTest {

	@Test
	public void test() {
		ECKey ec_key = new ECKey();
		
		ECKeypair key = ECKeypair.construct_private_key(ec_key); 
		
		//TODO test signatures
		//TODO test passwords
	}

}
