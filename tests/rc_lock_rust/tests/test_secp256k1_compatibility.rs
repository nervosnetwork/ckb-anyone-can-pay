#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{bytes::Bytes, bytes::BytesMut, packed::WitnessArgs, prelude::*, H256};
use lazy_static::lazy_static;
use rand::{thread_rng, Rng, SeedableRng};

use misc::{
    blake160, build_resolved_tx, debug_printer, gen_tx, gen_tx_with_grouped_args, gen_witness_lock,
    sign_tx, sign_tx_by_input_group, sign_tx_hash, DummyDataLoader, TestConfig, TestScheme,
    ERROR_ENCODING, ERROR_PUBKEY_BLAKE160_HASH, ERROR_WITNESS_SIZE, IDENTITY_FLAGS_PUBKEY_HASH,
    MAX_CYCLES,
};

mod misc;

lazy_static! {}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_unlock_with_args() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    let args = config.gen_args();

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(args, 1)], &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_with_extra_witness_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let extract_witness = vec![1, 2, 3, 4];
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![WitnessArgs::new_builder()
            .input_type(Some(Bytes::from(extract_witness)).pack())
            .build()
            .as_bytes()
            .pack()])
        .build();
    {
        let tx = sign_tx(&mut data_loader, tx.clone(), &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        let tx = sign_tx(&mut data_loader, tx, &mut config);
        let wrong_witness = tx
            .witnesses()
            .get(0)
            .map(|w| {
                WitnessArgs::new_unchecked(w.unpack())
                    .as_builder()
                    .output_type(Some(Bytes::from(vec![0])).pack())
                    .build()
            })
            .unwrap();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![wrong_witness.as_bytes().pack()])
            .build();
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0)
        );
    }
}

#[test]
fn test_sighash_all_with_grouped_inputs_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, Default::default());
    let args = config.gen_args();

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(args, 2)], &mut config);
    {
        let tx = sign_tx(&mut data_loader, tx.clone(), &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        let tx = sign_tx(&mut data_loader, tx.clone(), &mut config);
        let wrong_witness = tx
            .witnesses()
            .get(1)
            .map(|w| {
                WitnessArgs::new_unchecked(w.unpack())
                    .as_builder()
                    .input_type(Some(Bytes::from(vec![0])).pack())
                    .build()
            })
            .unwrap();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![
                tx.witnesses().get(0).unwrap(),
                wrong_witness.as_bytes().pack(),
            ])
            .build();
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let verify_result =
            TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
        assert_error_eq!(
            verify_result.unwrap_err(),
            ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0)
        );
    }
}

#[test]
fn test_sighash_all_with_2_different_inputs_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let mut config1 = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    let args1 = config1.gen_args();

    let mut config2 = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    let args2 = config2.gen_args();

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(args1, 2), (args2, 2)], &mut config1);
    let tx = sign_tx_by_input_group(tx, 0, 2, &mut config1);
    let tx = sign_tx_by_input_group(tx, 2, 2, &mut config2);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    // make it to wrong private key
    config.private_key = Generator::random_privkey();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0)
    );
}

#[test]
fn test_signing_wrong_tx_hash() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = {
        let mut rand_tx_hash = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut rand_tx_hash);
        sign_tx_hash(tx, &rand_tx_hash[..], &config)
    };
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0),
    );
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    config.set_scheme(TestScheme::LongWitness);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_2_in_2_out_cycles() {
    const CONSUME_CYCLES: u64 = 3356072;

    let mut data_loader = DummyDataLoader::new();

    let mut config1 = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);
    let config2 = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![(config1.gen_args(), 1), (config2.gen_args(), 1)],
        &mut config1,
    );
    let tx = sign_tx_by_input_group(tx, 0, 1, &config1);
    let tx = sign_tx_by_input_group(tx, 1, 1, &config2);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    let cycles = verify_result.expect("pass verification");
    // there is extra cycles, like parsing signature from witness, parsing args
    // so it will be larger than original secp256k1
    if cycles > (CONSUME_CYCLES + 150000) {
        println!("the cycles is: {}", cycles);
        assert!(false);
    }
}

#[test]
fn test_sighash_all_witness_append_junk_data() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(config.gen_args(), 2)], &mut config);
    let tx = sign_tx_by_input_group(tx, 0, 2, &mut config);
    let mut witnesses: Vec<_> = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    // append junk data to first witness
    let mut witness = Vec::new();
    witness.resize(witnesses[0].len(), 0);
    witness.copy_from_slice(&witnesses[0]);
    witness.push(0);
    witnesses[0] = witness.into();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(witnesses.into_iter().map(|w| w.pack()).collect())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0)
    );
}

#[test]
fn test_sighash_all_witness_args_ambiguity() {
    // This test case build tx with WitnessArgs(lock, data, "")
    // and try unlock with WitnessArgs(lock, "", data)
    //
    // this case will fail if contract use a naive function to digest witness.

    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(config.gen_args(), 2)], &mut config);
    let tx = sign_tx_by_input_group(tx, 0, 2, &mut config);
    let witnesses: Vec<_> = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    // move extra data to type_
    let witnesses: Vec<_> = witnesses
        .into_iter()
        .map(|witness| {
            // move data from input_type to output_type
            let witness = WitnessArgs::new_unchecked(witness);
            let data = witness.input_type().clone();
            witness
                .as_builder()
                .output_type(data)
                .input_type(Some(Bytes::new()).pack())
                .build()
        })
        .collect();

    let tx = tx
        .as_advanced_builder()
        .set_witnesses(witnesses.into_iter().map(|w| w.as_bytes().pack()).collect())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0),
    );
}

#[test]
fn test_sighash_all_witnesses_ambiguity() {
    // This test case sign tx with [witness1, "", witness2]
    // and try unlock with [witness1, witness2, ""]
    //
    // this case will fail if contract use a naive function to digest witness.

    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(config.gen_args(), 3)], &mut config);
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::new().pack(),
            Bytes::from(vec![42]).pack(),
        ])
        .build();
    let tx = sign_tx_by_input_group(tx, 0, 3, &mut config);

    // exchange witness position
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::from(vec![42]).pack(),
            Bytes::new().pack(),
        ])
        .build();

    assert_eq!(tx.witnesses().len(), tx.inputs().len());
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0),
    );
}

#[test]
fn test_sighash_all_cover_extra_witnesses() {
    let mut data_loader = DummyDataLoader::new();
    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, false);

    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(config.gen_args(), 2)], &mut config);
    let witness = Unpack::<Vec<_>>::unpack(&tx.witnesses()).remove(0);
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witness.pack(),
            Bytes::from(vec![42]).pack(),
            Bytes::new().pack(),
        ])
        .build();
    let tx = sign_tx_by_input_group(tx, 0, 3, &mut config);
    assert!(tx.witnesses().len() > tx.inputs().len());

    // change last witness
    let mut witnesses = Unpack::<Vec<_>>::unpack(&tx.witnesses());
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![
            witnesses.remove(0).pack(),
            witnesses.remove(1).pack(),
            Bytes::from(vec![0]).pack(),
        ])
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(60000000);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH).input_lock_script(0),
    );
}
