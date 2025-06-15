from block import Block
import hashlib
import time
import tkinter as tk
from tkinter import messagebox

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        
        self.create_block(proof=1, previous_hash='0') 

    def create_block(self, proof, previous_hash):
        block = Block(len(self.chain) + 1, previous_hash, time.time(), self.current_transactions, proof)
        self.current_transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]


    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[0:4] == '0000': 
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def add_transaction(self, sender, receiver, amount):
        self.current_transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })

        return self.get_previous_block().index + 1

    def is_chain_valid(self, chain):
        previous_block = chain[0] 
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block.previous_hash != previous_block.hash:
                return False

            previous_proof = previous_block.proof
            proof = block.proof
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            
            if hash_operation[0:4] != '0000':
                return False
            
            previous_block = block 
            block_index += 1
        return True

class BlockchainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Demo")
        self.blockchain = Blockchain()
        self.create_widgets()
        self.refresh_chain()

    def create_widgets(self):
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Sender:").grid(row=0, column=0)
        self.sender_entry = tk.Entry(frame)
        self.sender_entry.grid(row=0, column=1)
        self.sender_entry.insert(0, "Dung")
        self.sender_entry.config(state='readonly')

        tk.Label(frame, text="Receiver:").grid(row=1, column=0)
        self.receiver_entry = tk.Entry(frame)
        self.receiver_entry.grid(row=1, column=1)
        self.receiver_entry.insert(0, "Dung")
        self.receiver_entry.config(state='readonly')

        tk.Label(frame, text="Amount:").grid(row=2, column=0)
        self.amount_entry = tk.Entry(frame)
        self.amount_entry.grid(row=2, column=1)
        self.amount_entry.insert(0, "Dung")
        self.amount_entry.config(state='readonly')

        tk.Button(frame, text="Add Transaction", command=self.add_transaction).grid(row=3, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Mine Block", command=self.mine_block).grid(row=4, column=0, columnspan=2, pady=5)
        tk.Button(frame, text="Check Validity", command=self.check_validity).grid(row=5, column=0, columnspan=2, pady=5)

        self.chain_text = tk.Text(self.root, width=70, height=15)
        self.chain_text.pack(padx=10, pady=10)

    def add_transaction(self):
        sender = self.sender_entry.get()
        receiver = self.receiver_entry.get()
        amount = self.amount_entry.get()
        if not sender or not receiver or not amount:
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return
        self.blockchain.add_transaction(sender, receiver, amount)
        messagebox.showinfo("Success", "Transaction added.")

    def mine_block(self):
        previous_block = self.blockchain.get_previous_block()
        previous_proof = previous_block.proof
        new_proof = self.blockchain.proof_of_work(previous_proof)
        previous_hash = previous_block.hash
        self.blockchain.add_transaction('Genesis', 'Miner', 1)
        new_block = self.blockchain.create_block(new_proof, previous_hash)
        messagebox.showinfo("Block Mined", f"Block #{new_block.index} has been mined!")
        self.refresh_chain()

    def check_validity(self):
        valid = self.blockchain.is_chain_valid(self.blockchain.chain)
        messagebox.showinfo("Blockchain Validity", f"Blockchain is {'valid' if valid else 'invalid'}.")

    def refresh_chain(self):
        self.chain_text.delete(1.0, tk.END)
        for block in self.blockchain.chain:
            self.chain_text.insert(tk.END, f"Block #{block.index}\n")
            self.chain_text.insert(tk.END, f"Timestamp: {block.timestamp}\n")
            self.chain_text.insert(tk.END, f"Transactions: {block.transactions}\n")
            self.chain_text.insert(tk.END, f"Proof: {block.proof}\n")
            self.chain_text.insert(tk.END, f"Previous Hash: {block.previous_hash}\n")
            self.chain_text.insert(tk.END, f"Hash: {block.hash}\n")
            self.chain_text.insert(tk.END, "-----------------------------------\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainApp(root)
    root.mainloop()