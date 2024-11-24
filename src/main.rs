//! FROST CLI Implementation
//! 
//! A command-line tool implementing the FROST (Flexible Round-Optimized Schnorr Threshold) 
//! signatures protocol. This implementation demonstrates key generation, threshold signing,
//! and signature verification.

use clap::Parser;
use frost_dalek::*;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Serialize, Deserialize};

/// CLI configuration for the FROST threshold signature tool
#[derive(Parser)]
#[command(
    name = "frost-cli",
    about = "A tool for threshold signatures using FROST"
)]
struct Cli {
    /// Total number of participants in the threshold scheme
    #[arg(short, long)]
    participants: u32,
    
    /// Minimum number of participants required to create a valid signature
    #[arg(short, long)]
    threshold: u32,

    /// Directory where keys and signatures will be stored
    #[arg(short, long)]
    output: PathBuf,
}

/// Available commands for the CLI tool
#[derive(Parser)]
enum Commands {
    /// Generate new keys for the threshold signature scheme
    Generate {
        #[arg(short, long)]
        participants: u32,
        #[arg(short, long)]
        threshold: u32,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Sign a message using the threshold signature scheme
    Sign {
        #[arg(short, long)]
        message: String,
        #[arg(short)]
        output: PathBuf,
    },
    /// Verify a threshold signature
    Verify {
        #[arg(short, long)]
        message: String,
        #[arg(short, long)]
        signature: PathBuf,
    }
}

/// Structure for storing the group public key and parameters
#[derive(Serialize, Deserialize)]
struct StoredGroupKey {
    /// Minimum number of signers required
    threshold: u32,
    /// Total number of participants
    total_participants: u32,
    /// Serialized group public key
    key_bytes: [u8; 32],
}

/// Save the group public key and parameters to a JSON file
/// 
/// # Arguments
/// * `output_dir` - Directory where the key will be saved
/// * `group_key` - The FROST group public key
/// * `params` - Parameters of the threshold scheme
/// 
/// # Returns
/// * `std::io::Result<()>` - Success or filesystem error
fn save_group_key(output_dir: &Path, group_key: &GroupKey, params: &Parameters) -> std::io::Result<()> {
    // Create all directories in the path if they don't exist
    fs::create_dir_all(output_dir)?;
    
    let data = StoredGroupKey {
        threshold: params.t,
        total_participants: params.n,
        key_bytes: group_key.to_bytes(),
    };

    fs::write(
        output_dir.join("group_key.json"),
        serde_json::to_string_pretty(&data)?
    )
}

fn main() {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Validate threshold is not greater than total participants
    if cli.threshold > cli.participants {
        println!("Error: Threshold cannot be greater than number of participants");
        return;
    }
    
    println!("Generating keys for {} participants with threshold {}", 
             cli.participants, cli.threshold);
    
    // Initialize FROST parameters
    let params = Parameters {
        t: cli.threshold,
        n: cli.participants,
    };
    
    // Step 1: Generate participants and their coefficients
    let mut participants = Vec::new();
    let mut coefficients = Vec::new();
    
    // Create each participant with their initial key material
    for i in 1..=cli.participants {
        let (participant, participant_coefficients) = Participant::new(&params, i);
        println!("Generated participant {}", i);
        participants.push(participant);
        coefficients.push(participant_coefficients);
    }
    
    println!("\nGenerated {} participants successfully!", cli.participants);
    
    println!("\nVerifying participant proofs...");
    // Step 2: Verify each participant's proof
    for participant in &participants {
        for other in &participants {
            if participant.index != other.index {
                // Verify proof of secret key
                if let Err(_) = participant.proof_of_secret_key
                    .verify(&participant.index, &participant.public_key().unwrap()) {
                    println!("Error: Failed to verify proof for participant {}", participant.index);
                    return;
                }
            }
        }
    }

    println!("All proofs verified successfully!");

    // Step 3: Generate secret shares
    let mut states = Vec::new();

    println!("\nGenerating secret shares...");

    // Each participant generates their secret shares
    for (i, participant) in participants.iter().enumerate() {
        let mut other_participants = participants.clone();
        other_participants.remove(i); // Remove self from other participants
        
        match DistributedKeyGeneration::new(
            &params,
            &participant.index,
            &coefficients[i],
            &mut other_participants,
        ) {
            Ok(state) => {
                states.push(state);
                println!("Generated shares for participant {}", participant.index);
            }
            Err(_) => {
                println!("Error: Failed to generate shares for participant {}", participant.index);
                return;
            }
        }
    }

    // Step 4: Generate and collect secret shares
    println!("\nCollecting secret shares...");

    let mut all_secret_shares = Vec::new();

    for state in &states {
        match state.their_secret_shares() {
            Ok(shares) => {
                all_secret_shares.push(shares);
                println!("Collected shares from participant");
            }
            Err(_) => {
                println!("Error: Failed to get secret shares from a participant");
                return;
            }
        }
    }

    println!("Successfully generated and collected all shares!");

    println!("\nGenerating secret shares...");
    
    // Step 3: Generate secret shares
    let mut states = Vec::new();
    
    // Each participant generates their secret shares
    for (i, participant) in participants.iter().enumerate() {
        let mut other_participants = participants.clone();
        other_participants.remove(i); // Remove self from other participants
        
        match DistributedKeyGeneration::new(
            &params,
            &participant.index,
            &coefficients[i],
            &mut other_participants,
        ) {
            Ok(state) => {
                states.push(state);
                println!("Generated shares for participant {}", participant.index);
            }
            Err(_) => {
                println!("Error: Failed to generate shares for participant {}", participant.index);
                return;
            }
        }
    }
    
    // Step 4: Generate and collect secret shares
    println!("\nCollecting secret shares...");
    
    // Collect all shares into a vector BEFORE we do anything else with states
    let mut all_secret_shares = Vec::new();
    
    // First, collect all shares
    for state in &states{
        match state.their_secret_shares() {
            Ok(shares) => {
                all_secret_shares.push(shares);
                println!("Collected shares from participant");
            }
            Err(_) => {
                println!("Error: Failed to get secret shares from a participant");
                return;
            }
        }
    }

    println!("\nEntering round two...");
    
    // Step 5: Enter round two with the collected shares
    let mut round_two_states = Vec::new();
    
    // Now we can consume states as we're done collecting shares
    for (i, state) in states.clone().into_iter().enumerate() {
        // Collect the shares meant for this participant
        let mut my_shares = Vec::new();
        for (j, shares) in all_secret_shares.iter().enumerate() {
            if i != j {  // Don't include shares from self
                my_shares.push(shares[if j < i { i-1 } else { i }].clone());
            }
        }
        
        // Enter round two with collected shares
        match state.to_round_two(my_shares) {
            Ok(round_two_state) => {
                round_two_states.push(round_two_state);
                println!("Participant {} entered round two", i + 1);
            }
            Err(_) => {
                println!("Error: Participant {} failed to enter round two", i + 1);
                return;
            }
        }
    }
    println!("\nGenerating final keys...");
    
    // Step 6: Generate group key and secret keys
    let mut group_key = None;
    let mut secret_keys = Vec::new();
    
    // Each participant generates their key pair
    for (i, round_two_state) in round_two_states.into_iter().enumerate() {
        match round_two_state.finish(&participants[i].public_key().unwrap()) {
            Ok((group_k, secret_k)) => {
                // Store the first group key we see
                if group_key.is_none() {
                    group_key = Some(group_k);
                } else {
                    // Verify that all participants got the same group key
                    assert_eq!(group_key.as_ref().unwrap(), &group_k);
                }
                
                secret_keys.push(secret_k);
                println!("Generated keys for participant {}", i + 1);
            }
            Err(_) => {
                println!("Error: Failed to generate keys for participant {}", i + 1);
                return;
            }
        }
    }
    
    println!("\nKey generation completed successfully!");
    
    // Unwrap the group key (we know it exists if we got here)
    let group_key = group_key.unwrap();
    
    // Print some information about the generated keys
    println!("\nGenerated Keys:");
    println!("- Group Public Key generated");
    println!("- {} Secret Keys generated", secret_keys.len());
    
    // TODO: Save the keys to files
    // This would be our next step - implementing secure storage of:
    // 1. The group public key (can be public)
    // 2. Individual secret keys (need to be secured)
    
    let context = b"FROST-CLI-CONTEXT";
    let message = b"Test message";

    // Generate commitment shares
    let mut commitment_shares = Vec::new();
    for i in 1..=params.t {
        let (public_comshare, secret_comshare) = 
            generate_commitment_share_lists(&mut OsRng, i, 1);
        commitment_shares.push((public_comshare, secret_comshare));
    }

    // Create signature aggregator
    let mut aggregator = SignatureAggregator::new(
        params,
        group_key,
        context,
        message
    );

    // Add signers
    for (i, (public_comshare, _)) in commitment_shares.iter().enumerate() {
        aggregator.include_signer(
            (i + 1) as u32,
            public_comshare.commitments[0],
            secret_keys[i].to_public()  // Removed & as it implements Into
        );
    }

    let signers = aggregator.get_signers();
    let message_hash = compute_message_hash(context, message);

    // Generate partial signatures
    let mut partial_signatures = Vec::new();
    for (i, (_, mut secret_comshare)) in commitment_shares.into_iter().enumerate() {
        let partial_sig = secret_keys[i].sign(
            &message_hash,
            &group_key,
            &mut secret_comshare,
            0,  // Using first commitment
            signers
        ).unwrap();
        partial_signatures.push(partial_sig);
    }

    // Include partial signatures
    for sig in partial_signatures {
        aggregator.include_partial_signature(sig);
    }

    // Finalize and aggregate
    match aggregator.finalize() {
        Ok(aggregator) => {
            match aggregator.aggregate() {
                Ok(signature) => {
                    // Verify the signature
                    match signature.verify(&group_key, &message_hash) {
                        Ok(_) => println!("Signature verified successfully!"),
                        Err(_) => println!("Signature verification failed"),
                    }
                },
                Err(_) => println!("Failed to aggregate signature"),
            }
        },
        Err(_) => println!("Failed to finalize aggregator"),
    }

    if let Err(e) = save_group_key(&cli.output, &group_key, &params) {
        println!("Error saving group key: {}", e);
    } else {
        println!("Group key saved to {}", cli.output.display());
    }
}