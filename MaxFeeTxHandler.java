import java.util.ArrayList;
import java.util.HashMap;
import java.security.PublicKey;

public class MaxFeeTxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public UTXOPool utxoPool;

    public MaxFeeTxHandler(UTXOPool utxoPool) {
       this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     *
     */

    public boolean isValidTx(Transaction tx) {
        HashMap<UTXO, Boolean> claimedUXTOMap = new HashMap<UTXO, Boolean>();
        double outputSum = 0;

        ArrayList<Transaction.Output> outputs = tx.getOutputs();
        for(int index = 0; index < tx.numOutputs(); index++) {
            
            //rule 4: the output value is non-negative
            double outputValue = outputs.get(index).value;
            if (outputValue < 0) return false;
            outputSum += outputValue;
       
        }

        double inputSum = 0;
        ArrayList<Transaction.Input> inputs = tx.getInputs();
        for (int index = 0; index < tx.numInputs(); index ++) {

            Transaction.Input input = inputs.get(index);
            if (input == null) return false;

            byte[] preTxHash = input.prevTxHash;
            int outputIndex = input.outputIndex;
            UTXO utxo = new UTXO(preTxHash, outputIndex);
            //rule 1: output claimed by tx should be in the current UTXO pool
            if(!this.utxoPool.contains(utxo)) return false;
            
            // rule 3: utxo shouldn't be claimed multiple times by tx
            if(claimedUXTOMap.containsKey(utxo)) return false;

            claimedUXTOMap.put(utxo, true);    

            Transaction.Output output = this.utxoPool.getTxOutput(utxo);
            PublicKey address = output.address;
            byte[] msg = tx.getRawDataToSign(index);
            //rule 2: input signature is invalid
            if(!Crypto.verifySignature(address, msg, input.signature)) return false;

            inputSum += output.value;

        }

        //rule 5
        return inputSum >= outputSum;
    }

    public double calculateFee(Transaction tx) {
        double outputSum = 0;

        ArrayList<Transaction.Output> outputs = tx.getOutputs();
        for(int index = 0; index < tx.numOutputs(); index++) {
            
            //rule 4: the output value is non-negative
            double outputValue = outputs.get(index).value;
            if (outputValue < 0) return -1;
            outputSum += outputValue;
       
        }

        double inputSum = 0;
        for (Transaction.Input input: tx.getInputs()) {

            if (input == null) return -1;
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            if(!this.utxoPool.contains(utxo)) return -1;
            Transaction.Output output = this.utxoPool.getTxOutput(utxo);
            inputSum += output.value;

        }

        //rule 5
        return inputSum - outputSum;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> txs = new ArrayList<Transaction>();
        for (Transaction tx: possibleTxs) {
            if(isValidTx(tx)) {
                txs.add(tx);
                //update the UTXO pool
                //remove the claimed utxo
                for(Transaction.Input input: tx.getInputs()) {
                    UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                    this.utxoPool.removeUTXO(utxo);
                }
                //add the new utxo
                for(int index = 0; index < tx.numOutputs(); index++) {
                    UTXO utxo = new UTXO(tx.getHash(), index);
                    this.utxoPool.addUTXO(utxo, tx.getOutput(index));
                }
            }
        }
        return txs.toArray(new Transaction[txs.size()]); 
    }
}
