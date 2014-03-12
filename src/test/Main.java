package test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.google.bitcoin.core.AbstractPeerEventListener;
import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Peer;
import com.google.bitcoin.core.PeerEventListener;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.crypto.DeterministicKey;
import com.google.bitcoin.crypto.HDKeyDerivation;
import com.google.bitcoin.crypto.MnemonicCode;
import com.google.bitcoin.crypto.MnemonicException.MnemonicLengthException;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.*;
import com.google.bitcoin.utils.BriefLogFormatter;

public class Main {
	final static BigInteger maxKey = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
	static NetworkParameters params = null; 
	static MnemonicCode mnemonic = null;
	static String net = "main";
	static String filePrefix = null;
	
	static public void main(String[] args) {
		System.out.println("Starting Gryphon Wallet");
		
		BriefLogFormatter.init();

		// Figure out which network we should connect to. Each one gets its own set of files.
		if (net.equals("testnet")) {
		    params = TestNet3Params.get();
		    filePrefix = "test-data-testnet";
		} else if (net.equals("regtest")) {
		    params = RegTestParams.get();
		    filePrefix = "test-data-regtest";
		} else {
		    params = MainNetParams.get();
		    filePrefix = "test-data";
		}
		
		//test1GettingStartedTut();
		test2CryptoStuff();
		
		while(true) {
			
		}
	}
	
	static public void test1GettingStartedTut() {
		String addr = "17ujDgKJyhEi6vrQDANo2sqcHiJgUj4XLE";
		
		// Parse the address given as the first parameter.
		try {
			Address forwardingAddress = new Address(params, addr);
		} catch (AddressFormatException e) {
			System.err.println("AddressFormatException");
			System.exit(1);
		}
		
		//Get a listener for the network. 
		PeerEventListener listener = getListener();
		
		// Start up a basic app using a class that automates some boilerplate. Ensure we always have at least one key.
		WalletAppKit kit = new WalletAppKit(params, new File("/home/dragonfly/Gryphon"), filePrefix) {
		    /*@Override
		    protected void onSetupCompleted() {
		        // This is called in a background thread after startAndWait is called, as setting up various objects
		        // can do disk and network IO that may cause UI jank/stuttering in wallet apps if it were to be done
		        // on the main thread.
		        if (wallet().getKeychainSize() < 1)
		            wallet().addKey(new ECKey());
		    }*/
		};
		
		kit.setBlockingStartup(false);
		kit.setDownloadListener(listener);

		if (params == RegTestParams.get()) {
		    // Regression test mode is designed for testing and development only, so there's no public network for it.
		    // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.
		    kit.connectToLocalHost();
		}

		// Download the block chain and wait until it's done.
		kit.startAndWait();
	}
	
	static public void test2CryptoStuff() {
		
		//Create a mnemonic code.
		try {
			mnemonic = getMnemonic();
		} catch (IOException e) {
			System.err.println("Wordlist not found.");
			System.exit(1);
		}
		
		//Create a private key, a public key, and an address.
		ECKey key = new ECKey();
		printKeyProperties(key);
		
		//Add 1 to the private key and do again. Repeat several times.
		ECKey[] keys = new ECKey[5];
		BigInteger seed = byteArraytoBigInt(key.getPrivKeyBytes());
		BigInteger one = new BigInteger("1");
		System.out.println("Seed as bytes is " + Arrays.toString(key.getPrivKeyBytes()) + ".");
		System.out.println("Seed as a BigInteger is " + seed.toString() + ".");
		for(int i = 0; i < 5; i++) {
			seed.add(one).mod(maxKey);
			keys[i] = new ECKey(seed);
			System.out.println("New sequence key " + i + ".");
			printKeyProperties(keys[i]);
		}
		
		//Do some HD stuff. 
		DeterministicKey hdkey = HDKeyDerivation.createMasterPrivateKey(hexStringToByteArray("6C6DAB4542922D1B2FAFF15D98D2B8EEBEEABE3AAFDFD87F2F3DEEB3A36B9630"));
		//Get the public key. 
		DeterministicKey hdpub = hdkey.getPubOnly();
		//Derive some more keys. 
		ECKey hdprivd = hdkey.toECKey();
		ECKey hdpubd = hdpub.toECKey();
		//Derive some lower-order HD keys. 
		DeterministicKey hdkey0 = HDKeyDerivation.deriveChildKey(hdkey, 0);
		DeterministicKey hdkey1 = HDKeyDerivation.deriveChildKey(hdkey, 1);
		DeterministicKey hdpub0 = HDKeyDerivation.deriveChildKey(hdpub, 0);
		DeterministicKey hdpub1 = HDKeyDerivation.deriveChildKey(hdpub, 1);
		
		System.out.println("HD master private key: " + bytesToHex(hdkey.getPrivKeyBytes()) + ".");
		System.out.println("HD master public key: " + bytesToHex(hdkey.getPubKeyBytes()) + ".");
		System.out.println("Should be identical:  " + bytesToHex(hdpub.getPubKeyBytes()) + ".");

		System.out.println("HD master derived private key: " + bytesToHex(hdprivd.getPrivKeyBytes()) + ".");
		System.out.println("HD master derived public key: " + bytesToHex(hdprivd.getPubKey()) + ".");
		System.out.println("Should be identical:          " + bytesToHex(hdpubd.getPubKey()) + ".");
		
		System.out.println("HD 0 private key: " + bytesToHex(hdkey0.getPrivKeyBytes()) + ".");
		System.out.println("HD 0 public key:     " + bytesToHex(hdkey0.getPubKeyBytes()) + ".");
		System.out.println("Should be identical: " + bytesToHex(hdpub0.getPubKeyBytes()) + ".");
		
		System.out.println("HD 1 private key: " + bytesToHex(hdkey1.getPrivKeyBytes()) + ".");
		System.out.println("HD 1 public key:     " + bytesToHex(hdkey1.getPubKeyBytes()) + ".");
		System.out.println("Should be identical: " + bytesToHex(hdpub1.getPubKeyBytes()) + ".");
	}
	
	public static void test3EncryptedPrivateKeys() {
		
	}
	
	static public PeerEventListener getListener() {
		return new AbstractPeerEventListener(){
			int blocks = 0;
			int peers = 0;
			boolean downloading = false;
			int blocksleft = 0;

			@Override
			public void onBlocksDownloaded(Peer peer, Block b, int blocksleft) {
				blocks++;
				this.blocksleft = blocksleft;
			}

			@Override
			public void onChainDownloadStarted(Peer peer, int blocksleft) {
				downloading = true;
				this.blocksleft = blocksleft;
			}

			@Override
			public void onPeerConnected(Peer peer, int peercount) {
				peers = peercount;
			}

			@Override
			public void onPeerDisconnected(Peer peer, int peercount) {
				peers = peercount;
			}			@Override
			public void onTransaction(Peer peer, Transaction t) {
				
			}
			
			public void printStatus() {
				
			}
		};
	}
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static MnemonicCode getMnemonic() throws IOException {
		return new MnemonicCode();
	}
	
	public static void printKeyProperties(ECKey key) {
		System.out.println("The private key is " + bytesToHex(key.getPrivKeyBytes()) + ".");
		System.out.println("The public key is " + bytesToHex(key.getPubKey()) + ".");
		System.out.println("The address is " + key.toAddress(params) + ".");
		
		List<String> keygen = null;
		try {
			keygen = mnemonic.toMnemonic(key.getPrivKeyBytes());
		} catch (MnemonicLengthException e) {
			System.err.println("Improperly formatted mnemonic input.");
			System.exit(1);
		}
		System.out.println("The mnemonic is " + Arrays.toString(keygen.toArray()) + ".");
	}
	
	public static BigInteger byteArraytoBigInt(byte[] b) {
		byte[] B = new byte[b.length + 1];
		b[0] = (byte)0;
		for(int i = 0; i < b.length; i++) {
			B[i+1] = b[i];
		}
		return new BigInteger(B);
	}
}
