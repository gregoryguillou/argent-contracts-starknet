import pytest
import asyncio
import logging
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.business_logic.state.state import BlockInfo
from utils.Signer import Signer
from utils.utilities import deploy, declare, assert_revert, str_to_felt, assert_event_emmited
from utils.TransactionSender import TransactionSender
from starkware.cairo.common.hash_state import compute_hash_on_elements

LOGGER = logging.getLogger(__name__)

signer = Signer(123456789987654321)
signer2 = Signer(123456789987654322)
guardian = Signer(456789987654321123)
guardian_backup = Signer(354523164513454)

session_key = Signer(666666666666666666)
wrong_session_key = Signer(6767676767)

DEFAULT_TIMESTAMP = 1640991600
ESCAPE_SECURITY_PERIOD = 24*7*60*60

VERSION = str_to_felt('0.2.3')

IACCOUNT_ID = 0xf10dbd44


@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def get_starknet():
    starknet = await Starknet.empty()
    return starknet

def update_starknet_block(starknet, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
    starknet.state.state.block_info = BlockInfo(
        block_number=block_number,
        block_timestamp=block_timestamp,
        gas_price=0,
        sequencer_address=starknet.state.state.block_info.sequencer_address)

def reset_starknet_block(starknet):
    update_starknet_block(starknet=starknet)

@pytest.fixture
async def account_factory(get_starknet):
    starknet = get_starknet
    account = await deploy(starknet, "contracts/Argent2Account.cairo")
    plugin_class = await declare(starknet, "contracts/plugins/MultiSig.cairo")
    #await account.add_plugin(signer.public_key, 0).invoke()
    await account.initialize(plugin_class.class_hash, [signer.public_key, signer2.public_key, 2]).invoke()
    return account

@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp_class = await declare(starknet, "contracts/test/TestDapp.cairo")
    dapp = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp, dapp_class.class_hash

@pytest.fixture
async def plugin_default_factory(get_starknet):
    starknet = get_starknet
    plugin_default_class = await declare(starknet, "contracts/plugins/ArgentSecurity.cairo")
    plugin_default_session = await deploy(starknet, "contracts/plugins/ArgentSecurity.cairo")
    return plugin_default_session, plugin_default_class.class_hash

@pytest.fixture
async def plugin_factory(get_starknet):
    starknet = get_starknet
    plugin_class = await declare(starknet, "contracts/plugins/SessionKey.cairo")
    plugin_session = await deploy(starknet, "contracts/plugins/SessionKey.cairo")
    return plugin_session, plugin_class.class_hash

@pytest.mark.asyncio
async def test_direct_transaction_2_signers(account_factory, plugin_factory, dapp_factory):
    account = account_factory
    dapp, dapp_class = dapp_factory
    plugin, plugin_class = plugin_factory
    sender = TransactionSender(account)

    assert (await account.is_plugin(plugin_class).call()).result.success == (0)
    # Revert 1 wrong signer
    await assert_revert(sender.send_transaction_with_public_key([(account.contract_address, 'add_plugin', [plugin_class])], [signer, guardian]))
    tx_exec_info = await sender.send_transaction_with_public_key([(dapp.contract_address, 'set_number', [42])], [signer, signer2])
    assert (await dapp.get_number(account.contract_address).call()).result.number == 42

    # revert not enough signer
    await assert_revert(sender.send_transaction_with_public_key([(dapp.contract_address, 'set_number', [47])], [signer]))
    
    tx_exec_info = await sender.send_transaction_with_public_key([(dapp.contract_address, 'set_number', [47]), (dapp.contract_address, 'set_number', [30])], [signer, signer2])
    assert (await dapp.get_number(account.contract_address).call()).result.number == 30

@pytest.mark.asyncio
async def test_add_plugin(account_factory, plugin_factory):
    account = account_factory
    plugin, plugin_class = plugin_factory
    sender = TransactionSender(account)

    assert (await account.is_plugin(plugin_class).call()).result.success == (0)
    tx_exec_info = await sender.send_transaction_with_public_key([(account.contract_address, 'add_plugin', [plugin_class])], [signer, signer2])
    assert (await account.is_plugin(plugin_class).call()).result.success == (1)

def get_session_token(key, expires):
    session = [
        key,
        expires
    ]
    hash = compute_hash_on_elements(session)
    return signer.sign(hash)
