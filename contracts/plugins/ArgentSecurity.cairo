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

####################
# EVENTS
####################

@event
func signer_changed(new_signer: felt):
end

@event
func guardian_changed(new_guardian: felt):
end

@event
func guardian_backup_changed(new_guardian: felt):
end

@event
func escape_guardian_triggered(active_at: felt):
end

@event
func escape_signer_triggered(active_at: felt):
end

@event
func escape_canceled():
end

@event
func guardian_escaped(new_guardian: felt):
end

@event
func signer_escaped(new_signer: felt):
end

@event
func account_created(account: felt, key: felt, guardian: felt):
end

####################
# STORAGE VARIABLES
####################

@storage_var
func _signer() -> (res: felt):
end

@storage_var
func _guardian() -> (res: felt):
end

@storage_var
func _guardian_backup() -> (res: felt):
end

@storage_var
func _escape() -> (res: Escape):
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

    if call_array_len == 1:
        if call_array[0].to == tx_info.account_contract_address:
            tempvar signer_condition = (call_array[0].selector - ESCAPE_GUARDIAN_SELECTOR) * (call_array[0].selector - TRIGGER_ESCAPE_GUARDIAN_SELECTOR)
            tempvar guardian_condition = (call_array[0].selector - ESCAPE_SIGNER_SELECTOR) * (call_array[0].selector - TRIGGER_ESCAPE_SIGNER_SELECTOR)
            if signer_condition == 0:
                # validate signer signature
                validate_signer_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)
                return()
            end
            if guardian_condition == 0:
                # validate guardian signature
                validate_guardian_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)
                return()
            end
        end
        else:
            # make sure no call is to the account
            assert_no_self_call(tx_info.account_contract_address, call_array_len, call_array)
        end
        # validate signer and guardian signatures
        validate_signer_signature(tx_info.transaction_hash, tx_info.signature, tx_info.signature_len)
        validate_guardian_signature(tx_info.transaction_hash, tx_info.signature + 2, tx_info.signature_len - 2)
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
    let signer = [plugin_data]
    tempvar has_guardian = plugin_data_len - 2
    if has_guardian == 0:
        let guardian = [plugin_data +1]
        _guardian.write(guardian)
        _signer.write(signer)
    else:    
        _signer.write(signer)   
    end
    return ()
end

@external
func change_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        new_signer: felt
    ):
    # only called via execute
    assert_only_self()

    # change signer
    with_attr error_message("signer cannot be null"):
        assert_not_zero(new_signer)
    end
    _signer.write(new_signer)
    signer_changed.emit(new_signer=new_signer)
    return()
end

@external
func change_guardian{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        new_guardian: felt
    ):
    # only called via execute
    assert_only_self()
    
    # assert !(guardian_backup != 0 && new_guardian == 0)
    if new_guardian == 0:
        let (guardian_backup) = _guardian_backup.read()
        with_attr error_message("new guardian cannot be null"):
            assert guardian_backup = 0
        end
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
    else:
        tempvar syscall_ptr: felt* = syscall_ptr
        tempvar range_check_ptr = range_check_ptr
        tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
    end

    # change guardian
    _guardian.write(new_guardian)
    guardian_changed.emit(new_guardian=new_guardian)
    return()
end

@external
func change_guardian_backup{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        new_guardian: felt
    ):
    # only called via execute
    assert_only_self()

    # no backup when there is no guardian set
    assert_guardian_set()

    # change guardian
    _guardian_backup.write(new_guardian)
    guardian_backup_changed.emit(new_guardian=new_guardian)
    return()
end

@external
func trigger_escape_guardian{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    # only called via execute
    assert_only_self()

    # no escape when the guardian is not set
    assert_guardian_set()

    # store new escape
    let (block_timestamp) = get_block_timestamp()
    let new_escape: Escape = Escape(block_timestamp + ESCAPE_SECURITY_PERIOD, ESCAPE_TYPE_GUARDIAN)
    _escape.write(new_escape)
    escape_guardian_triggered.emit(active_at=block_timestamp + ESCAPE_SECURITY_PERIOD)
    return()
end

@external
func trigger_escape_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    # only called via execute
    assert_only_self()
    
    # no escape when there is no guardian set
    assert_guardian_set()

    # no escape if there is an guardian escape triggered by the signer in progress
    let (current_escape) = _escape.read()
    with_attr error_message("cannot overrride signer escape"):
        assert current_escape.active_at * (current_escape.type - ESCAPE_TYPE_SIGNER) = 0
    end

    # store new escape
    let (block_timestamp) = get_block_timestamp()
    let new_escape: Escape = Escape(block_timestamp + ESCAPE_SECURITY_PERIOD, ESCAPE_TYPE_SIGNER)
    _escape.write(new_escape)
    escape_signer_triggered.emit(active_at=block_timestamp + ESCAPE_SECURITY_PERIOD)
    return()
end

@external
func cancel_escape{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():

    # only called via execute
    assert_only_self()

    # validate there is an active escape
    let (current_escape) = _escape.read()
    with_attr error_message("no escape to cancel"):
        assert_not_zero(current_escape.active_at)
    end

    # clear escape
    let new_escape: Escape = Escape(0, 0)
    _escape.write(new_escape)
    escape_canceled.emit()
    return()
end

@external
func escape_guardian{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        new_guardian: felt
    ):
    alloc_locals

    # only called via execute
    assert_only_self()
    # no escape when the guardian is not set
    assert_guardian_set()
    
    let (current_escape) = _escape.read()
    let (block_timestamp) = get_block_timestamp()
    with_attr error_message("escape is not valid"):
        # assert there is an active escape
        assert_not_zero(current_escape.active_at)
        assert_le(current_escape.active_at, block_timestamp)
        # assert the escape was triggered by the signer
        assert current_escape.type = ESCAPE_TYPE_GUARDIAN
    end

    # clear escape
    let new_escape: Escape = Escape(0, 0)
    _escape.write(new_escape)

    # change guardian
    assert_not_zero(new_guardian)
    _guardian.write(new_guardian)
    guardian_escaped.emit(new_guardian=new_guardian)

    return()
end

@external
func escape_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        new_signer: felt
    ):
    alloc_locals

    # only called via execute
    assert_only_self()
    # no escape when the guardian is not set
    assert_guardian_set()

    let (current_escape) = _escape.read()
    let (block_timestamp) = get_block_timestamp()
    with_attr error_message("escape is not valid"):
        # validate there is an active escape
        assert_not_zero(current_escape.active_at)
        assert_le(current_escape.active_at, block_timestamp)
        # assert the escape was triggered by the guardian
        assert current_escape.type = ESCAPE_TYPE_SIGNER
    end

    # clear escape
    let new_escape: Escape = Escape(0, 0)
    _escape.write(new_escape)

    # change signer
    assert_not_zero(new_signer)
    _signer.write(new_signer)
    signer_escaped.emit(new_signer=new_signer)

    return()
end

####################
# VIEW FUNCTIONS
####################

@view
func is_valid_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        hash: felt,
        sig_len: felt,
        sig: felt*
    ) -> (is_valid: felt):
    alloc_locals

    let (is_signer_sig_valid) = validate_signer_signature(hash, sig, sig_len)
    let (is_guardian_sig_valid) = validate_guardian_signature(hash, sig + 2, sig_len - 2)
    
    # Cairo's way of doing `&&` is by multiplying the two booleans.
    return (is_valid=is_signer_sig_valid * is_guardian_sig_valid)
end

@view
func get_signer{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (signer: felt):
    let (res) = _signer.read()
    return (signer=res)
end

@view
func get_guardian{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (guardian: felt):
    let (res) = _guardian.read()
    return (guardian=res)
end

@view
func get_guardian_backup{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (guardian_backup: felt):
    let (res) = _guardian_backup.read()
    return (guardian_backup=res)
end

@view
func get_escape{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } () -> (active_at: felt, type: felt):
    let (res) = _escape.read()
    return (active_at=res.active_at, type=res.type)
end

####################
# INTERNAL FUNCTIONS
####################

func assert_initialized{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    let (signer) = _signer.read()
    with_attr error_message("account not initialized"):
        assert_not_zero(signer)
    end
    return()
end

func assert_guardian_set{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } ():
    let (guardian) = _guardian.read()
    with_attr error_message("guardian must be set"):
        assert_not_zero(guardian)
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
        signatures: felt*,
        signatures_len: felt
    ) -> (is_valid: felt):
    with_attr error_message("signer signature invalid"):
        assert_nn(signatures_len - 2)
        let (signer) = _signer.read()
        verify_ecdsa_signature(
            message=message,
            public_key=signer,
            signature_r=signatures[0],
            signature_s=signatures[1])
    end
    return(is_valid=TRUE)
end

@view
func validate_signer_signature2{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        message: felt, 
        signatures_len: felt,
        signatures: felt*
    ) -> (is_valid: felt):
    with_attr error_message("signer signature invalid"):
        assert_nn(signatures_len - 2)
        let (signer) = _signer.read()
        verify_ecdsa_signature(
            message=message,
            public_key=signer,
            signature_r=signatures[0],
            signature_s=signatures[1])
    end
    return(is_valid=TRUE)
end

func validate_guardian_signature{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        ecdsa_ptr: SignatureBuiltin*,
        range_check_ptr
    } (
        message: felt,
        signatures: felt*,
        signatures_len: felt
    ) -> (is_valid: felt):
    alloc_locals
    let (guardian) = _guardian.read()
    if guardian == 0:
        return(is_valid=TRUE)
    else:
        with_attr error_message("guardian signature invalid"):
            if signatures_len == 2:
                # must be signed by guardian
                verify_ecdsa_signature(
                    message=message,
                    public_key=guardian,
                    signature_r=signatures[0],
                    signature_s=signatures[1])
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            else:
                # must be signed by guardian_backup
                assert signatures_len = 4
                assert (signatures[0] + signatures[1]) = 0
                let (guardian_backup) = _guardian_backup.read()
                verify_ecdsa_signature(
                    message=message,
                    public_key=guardian_backup,
                    signature_r=signatures[2],
                    signature_s=signatures[3])
                tempvar syscall_ptr: felt* = syscall_ptr
                tempvar range_check_ptr = range_check_ptr
                tempvar pedersen_ptr: HashBuiltin* = pedersen_ptr
            end
        end
        return(is_valid=TRUE)
    end
end