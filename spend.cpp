// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/util/setup_common.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>
#include <wallet/spend.h>
#include <key_io.h>


namespace wallet {
namespace {

    const TestingSetup* g_setup;
    static std::unique_ptr<CWallet> g_wallet_ptr;
    static Chainstate* g_chainstate = nullptr;

    void initialize_setup() {
        static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
        g_setup = testing_setup.get();
        const auto& node{g_setup->m_node};
        g_chainstate = &node.chainman->ActiveChainstate();
        g_wallet_ptr = std::make_unique<CWallet>(node.chain.get(), "", CreateMockableWalletDatabase());
    }

    // Randomly choses one enum from OutputType.
    static OutputType RandomOutputType(FuzzedDataProvider& fuzzed_data_provider) {
        return static_cast<OutputType>(fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 4));
    }

    FUZZ_TARGET_INIT(spend, initialize_setup) {
        
        FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
        CWallet& wallet = *g_wallet_ptr;
        {
            LOCK(wallet.cs_wallet);
            wallet.SetLastBlockProcessed(g_chainstate->m_chain.Height(), g_chainstate->m_chain.Tip()->GetBlockHash());
        }

        if(fuzzed_data_provider.ConsumeBool()) {
            wallet.m_consolidate_feerate = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        }
        if(fuzzed_data_provider.ConsumeBool()) {
            wallet.m_default_change_type = RandomOutputType(fuzzed_data_provider);
        }
        if(fuzzed_data_provider.ConsumeBool()) {
            wallet.m_discard_rate = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        }
        if(fuzzed_data_provider.ConsumeBool()) {
            wallet.m_pay_tx_fee = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
            wallet.m_min_fee = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        }
        wallet.m_allow_fallback_fee = fuzzed_data_provider.ConsumeBool();
        wallet.m_signal_rbf = fuzzed_data_provider.ConsumeBool();
        if(fuzzed_data_provider.ConsumeBool()) {
            wallet.m_min_fee = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        }

        // GetScriptForDestination(*Assert(&wallet->GetNewDestination(RandomOutputType(fuzzed_data_provider), "dummy")))
        std::vector<CRecipient> recipients = {{GetScriptForRawPubKey(coinbaseKey.GetPubKey())),/*nAmount=*/ConsumeMoney(fuzzed_data_provider, /*max=*/COIN), /*fSubtractFeeFromAmount=*/fuzzed_data_provider.ConsumeBool()}};
        
        constexpr int RANDOM_CHANGE_POSITION = -1;

        CCoinControl coin_control;
        if(fuzzed_data_provider.ConsumeBool()) {
            coin_control.m_signal_bip125_rbf = fuzzed_data_provider.ConsumeBool();
        }
        coin_control.m_avoid_address_reuse = fuzzed_data_provider.ConsumeBool();
        coin_control.m_avoid_partial_spends = fuzzed_data_provider.ConsumeBool();
        coin_control.fOverrideFeeRate = fuzzed_data_provider.ConsumeBool();
        coin_control.m_include_unsafe_inputs = fuzzed_data_provider.ConsumeBool();
        coin_control.fAllowWatchOnly = fuzzed_data_provider.ConsumeBool();
        if(fuzzed_data_provider.ConsumeBool()) {
            coin_control.m_change_type = RandomOutputType(fuzzed_data_provider);
        }
        if(fuzzed_data_provider.ConsumeBool()) {
            coin_control.destChange = DecodeDestination(fuzzed_data_provider.ConsumeRandomLengthString());
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            coin_control.m_feerate = CFeeRate{ConsumeMoney(fuzzed_data_provider, /*max=*/COIN)};
        }
        if (fuzzed_data_provider.ConsumeBool()) {
            coin_control.m_confirm_target = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
        }
        coin_control.m_min_depth = fuzzed_data_provider.ConsumeIntegral<int>();
        coin_control.m_max_depth = fuzzed_data_provider.ConsumeIntegral<int>();
        // m_fee_mode and m_external_provider are left to include (they might be of no use here)

        bool sign = fuzzed_data_provider.ConsumeBool();

        // Covers CreateTransaction() and internal functions.
        (void)CreateTransaction(wallet, recipients, RANDOM_CHANGE_POSITION, coin_control, sign);

        // TODO: FundTransaction().
    }
} // namespace
} // namespace wallet
