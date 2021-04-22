use ark_ff::Field;
use ark_relations::r1cs::ConstraintSynthesizer;

pub struct MerkleTreeVerification<F: Field> {
    
}

impl<F: Field> ConstraintSynthesizer<F> for MerkleTreeVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        
    }
}