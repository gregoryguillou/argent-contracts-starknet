%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash_state import (
    HashState, hash_finalize, hash_init, hash_update, hash_update_single)
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_not_zero, assert_nn, assert_le
from starkware.starknet.common.syscalls import (
    call_contract, get_tx_info, get_contract_address, get_caller_address, get_block_timestamp
)

from starkware.cairo.common.bool import (TRUE, FALSE)

struct CallArray:
    member to: felt
    member selector: felt
    member data_offset: felt
    member data_len: felt
end

struct Escape:
    member active_at: felt
    member type: felt
end


####################
# CONSTANTS
####################

const CHANGE_SIGNER_SELECTOR = 1540130945889430637313403138889853410180247761946478946165786566748520529557
const CHANGE_GUARDIAN_SELECTOR = 1374386526556551464817815908276843861478960435557596145330240747921847320237
const TRIGGER_ESCAPE_GUARDIAN_SELECTOR = 73865429733192804476769961144708816295126306469589518371407068321865763651
const TRIGGER_ESCAPE_SIGNER_SELECTOR = 651891265762986954898774236860523560457159526623523844149280938288756256223
const ESCAPE_GUARDIAN_SELECTOR = 1662889347576632967292303062205906116436469425870979472602094601074614456040
const ESCAPE_SIGNER_SELECTOR = 578307412324655990419134484880427622068887477430675222732446709420063579565
const CANCEL_ESCAPE_SELECTOR = 992575500541331354489361836180456905167517944319528538469723604173440834912

const ESCAPE_SECURITY_PERIOD = 7*24*60*60 # set to e.g. 7 days in prod

const ESCAPE_TYPE_GUARDIAN = 1
const ESCAPE_TYPE_SIGNER = 2

const SIG_LENGTH = 2 # sig length. here sig should be sig_r, sig_s

####################
# EVENTS
####################

@event
func signer_changed(new_signer: felt):
end

@event
func account_created(account: felt, key: felt, guardian: felt):
end

####################
# STORAGE VARIABLES
####################

@storage_var
func _confirmations_required() -> (res : felt):
end

@storage_var
func _owners_len() -> (res : felt):
end

@storage_var
func _owners(index : felt) -> (res : felt):
end

@storage_var
func _is_owner(address : felt) -> (res : felt):
end

@storage_var
func _has_signed(address : felt) -> (res : felt):
end

####################
# PLUGIN INTERFACE
####################

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

    # make sure the account is initialized
    assert_initialized()
    
    # get the tx info
    let (tx_info) = get_tx_info()

    #get number of signatures
    let nb_sig = tx_info.signature_len / SIG_LENGTH
    let (confirmations_required) = _confirmations_required.read()

    if call_array_len == 1:
        if call_array[0].to == tx_info.account_contract_address:
            is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature, plugin_data_len, plugin_data)
            with_attr error_message("invalid number of required confirmations"):
                assert_le(confirmations_required, nb_sig)
            end
            clear_confirmations(plugin_data_len, plugin_data)
            return()
        end
        else:
            # make sure no call is to the account
            #assert_no_self_call(tx_info.account_contract_address, call_array_len, call_array)
            is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature, plugin_data_len, plugin_data)
            with_attr error_message("invalid number of required confirmations"):
                assert_le(confirmations_required, nb_sig)
            end
            clear_confirmations(plugin_data_len, plugin_data)
            return()
        end

    is_valid_signature(tx_info.transaction_hash, tx_info.signature_len, tx_info.signature, plugin_data_len, plugin_data)
    with_attr error_message("invalid number of required confirmations"):
        assert_le(confirmations_required, nb_sig)
    end
    clear_confirmations(plugin_data_len, plugin_data)
    return()
end

####################
# EXTERNAL FUNCTIONS
####################

@external
func initialize{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        plugin_data_len: felt,
        plugin_data: felt*
    ) -> ():
    alloc_locals

    # last param is the confirmations_required number.
    let confirmations_required = [plugin_data + plugin_data_len - 1]
    # Owners length is the array passed minus the last params (confirmations required)
    let owners_len = plugin_data_len - 1
    with_attr error_message("invalid number of required confirmations"):
        assert_le(confirmations_required, owners_len)
    end

    _owners_len.write(value=owners_len)
    _set_owners(owners_index=0, owners_len=owners_len, owners=plugin_data)
    _confirmations_required.write(value=confirmations_required)
    return ()
end

####################
# VIEW FUNCTIONS
####################

@view
func is_owner{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address : felt) -> (res : felt):
    let (res) = _is_owner.read(address=address)
    return (res)
end

@view
func has_signed{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(address : felt) -> (res : felt):
    let (res) = _has_signed.read(address=address)
    return (res)
end

@view
func is_valid_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        hash: felt,
        sig_len: felt,
        sig: felt*,
        pub_len: felt,
        pub: felt*
    ) -> (is_valid: felt):
    alloc_locals

    if sig_len == 0:
        return (TRUE)
    end

    let (is_signer_sig_valid) = validate_signer_signature(hash, pub, sig, sig_len)

    if is_signer_sig_valid == TRUE:
        return is_valid_signature(hash, sig_len - SIG_LENGTH, sig + SIG_LENGTH, pub_len - 1, pub + 1)
    end
    return (FALSE)

    # Cairo's way of doing `&&` is by multiplying the two booleans.
    #return (is_valid=is_signer_sig_valid * is_valid_signature(hash, sig_len -2, sig + 2) )
end

@view
func _get_owners{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(
        owners_index : felt,
        owners_len : felt,
        owners : felt*,
    ):
    if owners_index == owners_len:
        return ()
    end

    let (owner) = _owners.read(index=owners_index)
    assert owners[owners_index] = owner

    _get_owners(owners_index=owners_index + 1, owners_len=owners_len, owners=owners)
    return ()
end

@view
func get_owners{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (
        owners_len : felt,
        owners : felt*,
    ):
    alloc_locals
    let (owners) = alloc()
    let (owners_len) = _owners_len.read()
    if owners_len == 0:
        return (owners_len=owners_len, owners=owners)
    end

    # Recursively add owners from storage to the owners array
    _get_owners(owners_index=0, owners_len=owners_len, owners=owners)
    return (owners_len=owners_len, owners=owners)
end

####################
# INTERNAL FUNCTIONS
####################

func assert_initialized{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    let (signer) = _owners_len.read()
    with_attr error_message("account not initialized"):
        assert_not_zero(signer)
    end
    return()
end

func assert_only_self{
        syscall_ptr: felt*
    } () -> ():
    let (self) = get_contract_address()
    let (caller_address) = get_caller_address()
    with_attr error_message("must be called via execute"):
        assert self = caller_address
    end
    return()
end

func assert_no_self_call(
        self: felt,
        call_array_len: felt,
        call_array: CallArray*
    ):
    if call_array_len == 0:
        return ()
    end
    assert_not_zero(call_array[0].to - self)
    assert_no_self_call(self, call_array_len - 1, call_array + CallArray.SIZE)
    return()
end

func validate_signer_signature{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        message: felt, 
        public_key: felt*, 
        signatures: felt*,
        signatures_len: felt
    ) -> (is_valid: felt):
    let (is_caller_owner) = is_owner(address=[public_key])
    let (has_signer_already_signed) = has_signed(address=[public_key])
    with_attr error_message("not owner"):
        assert is_caller_owner = TRUE
    end
    with_attr error_message("owner already signed"):
        assert has_signer_already_signed = FALSE
    end
    with_attr error_message("signer signature invalid"):
        # change sig size to SIG_LENGTH?
        #assert_nn(signatures_len - SIG_LENGTH) 
        # TODO does not work need a way to get the correct signer.
        verify_ecdsa_signature(
            message=message,
            public_key=[public_key],
            signature_r=signatures[0],
            signature_s=signatures[1])
    end
    _has_signed.write(address=[public_key], value=TRUE)
    return(is_valid=TRUE)
end

func clear_confirmations{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (        
        plugin_data_len: felt,
        plugin_data: felt*
    ):
    if plugin_data_len == 0:
        return ()
    end
    _has_signed.write(address=[plugin_data], value=FALSE)
    clear_confirmations(plugin_data_len - 1, plugin_data + 1)
    return ()
end

####################
# HELPERS FUNCTIONS
####################

func _set_owners{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
    }(
        owners_index : felt,
        owners_len : felt,
        owners : felt*,
    ):
    if owners_index == owners_len:
        return ()
    end

     # Write the current iteration to storage
    _owners.write(index=owners_index, value=[owners])
    _is_owner.write(address=[owners], value=TRUE)

    # Recursively write the rest
    _set_owners(owners_index=owners_index + 1, owners_len=owners_len, owners=owners + 1)
    return ()
end