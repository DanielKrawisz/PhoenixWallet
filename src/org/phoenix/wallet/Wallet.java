package org.phoenix.wallet;

import java.util.LinkedList;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.Transaction;

public interface Wallet {
	public int balance(); //The balance of the wallet. 
	public boolean password_protected(); //Whether this wallet is password protected. 
	public boolean can_sign(Transaction t); //Whether the wallet can sign this transaction. 
	public boolean can_make_valid(Transaction t); //Whether the wallet can make the transaction valid by signing it. 
	public LinkedList<Transaction> history(); //Returns a history of the 
	public LinkedList<Transaction> transactions(); //Get the list of transactions this wallet has available. 
	public LinkedList<Address> get_listening_addresses(); //Get the addresses that this wallet listens for. 
	public LinkedList<Address> get_spent_addresses(); //Get the addresses that have been spent from. 
	public LinkedList<Address> get_unspent_addresses(); //Get addresses that never been spent.
	public LinkedList<Address> get_full_addresses(); //Get addresses that have BTC in them. 
	public int total_factors(); //The number of factors in this wallet. 
	public int required_factors(); //The number of factors required to sign a transaction. 
}
