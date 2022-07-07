%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import (
    HashState, hash_finalize, hash_init, hash_update, hash_update_single)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_nn
from starkware.starknet.common.syscalls import (
    call_contract, get_tx_info, get_contract_address, get_caller_address, get_block_timestamp)
#from starkware.cairo.common.dict import dict_new, dict_read, dict_write

@contract_interface
namespace IAccount:
    func is_valid_signature(hash: felt, sig_len: felt, sig: felt*):
    end 
    func validate_signer_signature2(message: felt, signatures_len: felt, signatures: felt*):
    end
end

struct CallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end

struct StarkNet_Domain:
    member name : felt
    member version : felt
    member chain_id : felt
end

struct Policy:
    member contract : felt
    member function : felt
end

struct Session:
    member key : felt
    member validity : felt
    member policy_len : felt
    member policy : felt*
end

# only for tmp storage todo remove??
@storage_var
func _policy_hash(hash: felt) -> (res: felt):
end

@external
func validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*,
        call_array_len: felt,
        call_array: CallArray*,
        calldata_len: felt,
        calldata: felt*
    ):
    alloc_locals
    
    # get the tx info
    let (tx_info) = get_tx_info()

    # check is the session has expired
    let session_expires = [plugin_data + 1]
    with_attr error_message("session expired"):
        let (now) = get_block_timestamp()
        assert_nn(session_expires - now)
    end
    # check if the session is approved
    let session_key = [plugin_data]
    # policy is after sessionKey, expiration and sig1 and 2. hence 4
    let (hash) = compute_hash(session_key, session_expires, plugin_data_len - 4, plugin_data + 4)
    with_attr error_message("unauthorised session"):
        IAccount.validate_signer_signature2(
            contract_address=tx_info.account_contract_address,
            message=hash,
            signatures_len=2,
            signatures=plugin_data + 2
        )
    end

    # see later how to use Dict/Map instead of storage
    #let (policy : DictAccess*) = dict_new()
    write_policy(plugin_data_len - 4, plugin_data + 4)
    check_policy(call_array_len, call_array)
    # reset storage
    clean_policy(plugin_data_len - 4, plugin_data + 4)

    # check if the tx is signed by the session key
    with_attr error_message("session key signature invalid"):
        verify_ecdsa_signature(
            message=tx_info.transaction_hash,
            public_key=session_key,
            signature_r=tx_info.signature[0],
            signature_s=tx_info.signature[1]
        )
    end
    return()
end

# compute hash of (to, selector) to be check against all following calls
func write_policy{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*
     ):
    alloc_locals

    if plugin_data_len == 0:
        return()
    end

    let (hash) = hash2{hash_ptr=pedersen_ptr}([plugin_data], [plugin_data +1])
    _policy_hash.write(hash=hash, value=1)
    write_policy(plugin_data_len - 2, plugin_data + 2)
    return()
end

func check_policy{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        call_array_len: felt,
        call_array: CallArray*
     ):
    alloc_locals

    if call_array_len == 0:
        return()
    end

    let (hash) = hash2{hash_ptr=pedersen_ptr}([call_array].to, [call_array].selector)
    let (res) = _policy_hash.read(hash=hash)
    with_attr error_message("unauthorised policy"):
        assert_not_zero(res)
    end
    return()

end

func clean_policy{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*
     ):
    alloc_locals

    if plugin_data_len == 0:
        return()
    end

    let (hash) = hash2{hash_ptr=pedersen_ptr}([plugin_data], [plugin_data +1])
    _policy_hash.write(hash=hash, value=0)
    clean_policy(plugin_data_len - 2, plugin_data + 2)
    return()

end

func compute_hash{pedersen_ptr: HashBuiltin*}(session_key: felt, session_expires: felt, policy_len: felt, policy: felt*) -> (hash : felt):
    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, session_key)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, session_expires)
        let (hash_state_ptr) = hash_update(hash_state_ptr, policy, policy_len)
        let (res) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
    end
    return (hash=res)
end
