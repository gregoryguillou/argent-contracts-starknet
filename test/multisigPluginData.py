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
    plugin_multisig_class = await declare(starknet, "contracts/plugins/MultiSigPluginData.cairo")
    #await account.add_plugin(signer.public_key, 0).invoke()
    await account.initialize(plugin_multisig_class.class_hash, [signer.public_key, signer2.public_key, 2]).invoke()
    return account, plugin_multisig_class.class_hash

@pytest.fixture
async def dapp_factory(get_starknet):
    starknet = get_starknet
    dapp_class = await declare(starknet, "contracts/test/TestDapp.cairo")
    dapp = await deploy(starknet, "contracts/test/TestDapp.cairo")
    return dapp, dapp_class.class_hash

@pytest.fixture
async def plugin_factory(get_starknet):
    starknet = get_starknet
    plugin_class = await declare(starknet, "contracts/plugins/SessionKey.cairo")
    plugin_session = await deploy(starknet, "contracts/plugins/SessionKey.cairo")
    return plugin_session, plugin_class.class_hash

@pytest.fixture
async def plugin__multisig_factory(get_starknet):
    starknet = get_starknet
    plugin_multisig_class = await declare(starknet, "contracts/plugins/MultiSigPluginData.cairo")
    plugin__multisig_session = await deploy(starknet, "contracts/plugins/MultiSigPluginData.cairo")
    return plugin__multisig_session, plugin_multisig_class.class_hash

@pytest.mark.asyncio
async def test_direct_transaction_2_signers(account_factory, dapp_factory):
    account, plugin_multisig_class = account_factory
    dapp, dapp_class = dapp_factory
    sender = TransactionSender(account)

    tx_exec_info = await sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_multisig_class, signer.public_key, signer2.public_key]),
            (dapp.contract_address, 'set_number', [47])
        ], 
        [signer, signer2])

    assert (await dapp.get_number(account.contract_address).call()).result.number == 47

    await assert_revert(sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_multisig_class, signer.public_key]),
            (dapp.contract_address, 'set_number', [42])
        ], 
        [signer]),
        "invalid number of required confirmations"
    )

    await assert_revert(sender.send_transaction(
        [
            (account.contract_address, 'use_plugin', [plugin_multisig_class, signer.public_key, signer.public_key]),
            (dapp.contract_address, 'set_number', [42])
        ], 
        [signer, signer]),
        "owner already signed"
    )