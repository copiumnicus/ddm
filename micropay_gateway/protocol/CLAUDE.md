# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Status: Work in Progress**

This is a Rust library implementing a micropayment gateway protocol. The protocol enables clients to use cryptographic vouchers to pay for services (queries) from vendors, with real-time credit tracking and cost settlement.

## Core Architecture (In Development)

The protocol is being built around three main components:

### 1. **VoucherAuth** (src/vauth.rs)
Validates voucher authenticity and authorization through:
- **Static validation**: Cryptographic signature, non-zero atoms, correct vendor
- **Volatile validation**: Subscription status, collateral sufficiency, voucher spend status

Vouchers use sequential nonces (similar to blockchain transactions) that must increase by exactly 1.

### 2. **CreditTrack** (src/ctrack.rs)
Calculates available client credit based on:
- **Unspent atoms**: Sum of unspent vouchers
- **Unmarked cost**: Accumulated "dust" costs smaller than first unspent voucher
- **Locked cost**: Reserved atoms for parallel queries
- **Cap**: Risk-adjusted collateral to prevent over-consumption

The risk model accounts for clients potentially being subscribed to multiple vendors simultaneously.

### 3. **Engine** (src/engine.rs)
Orchestrates the request lifecycle:
1. `accept_session()` - Validates voucher for new session
2. `accept_query()` - Checks credit availability and locks approximate cost
3. Process query (external to engine)
4. `settle_query()` - Settles actual cost based on time + data

Costs are calculated as: `(hours * hour_price) + (gigabytes * gb_price)` converted to atoms.

## Trait System (src/traits.rs)

Generic traits allow different implementations:

- **Voucher<U, K>**: Payment instrument interface
- **VoucherTracker<V, U>**: Voucher storage with spend tracking
- **UnmarkedCostTracker<U>**: Cost accumulation tracking
- **ChainOracle<U, K>**: On-chain data provider (collateral, subscriptions)

### Outstanding Balance Module (src/obalance.rs)
Currently implementing async outstanding balance tracking with:
- Generic `OutstandingBalanceRecord` trait
- `ClientOutstandingBalanceOp` for async database operations
- `OutstandingBalanceTracker` for concurrent balance management

This will provide the production `UnmarkedCostTracker` implementation.

## Key Concepts

**Atoms**: Smallest unit of value (configurable decimals via `Voucher::DECIMALS`)

**Voucher Flow**: Clients sign sequential vouchers (V0, V1, V2...). As costs accumulate and exceed a voucher's atoms, it's marked spent. Clients must provide newer vouchers to continue.

**Risk Adjustment**: Collateral divided by `(total_subscribed + expand_risk)` to account for chain state lag.

## Development Commands

```bash
# Build
cargo build

# Run tests
cargo test

# Run specific test
cargo test test_op_outstanding_balance

# Check without building
cargo check
```
