# 🏦 Secure Joint Bank

### 🔐 Cryptographically Enforced Threshold Authorization System for Joint Bank Transactions

<p align="center">
  <strong>Secure • Cryptographic • Threshold-Based • Tamper-Evident</strong>
</p>

<p align="center">
  A secure joint-account transaction authorization system that ensures a transaction cannot be executed unless the required number of genuine account holders provide valid cryptographic approvals.
</p>

---

## 🌟 Overview

**Secure Joint Bank** is an academic banking-security project designed for **joint bank accounts**, where multiple account holders must approve a transaction before it can be executed.

Unlike a traditional database-only approval system, this project does **not trust the database status alone**.

Instead, every transaction is protected using:

- 🔑 RSA Digital Signatures
- #️⃣ SHA-256 Transaction Hashing
- 👥 Threshold-Based Authorization
- 🔐 JWT Authentication
- 🔒 Bcrypt Password Hashing
- 🛡️ Tamper Detection
- 📋 Security Event Logging

### Core Security Principle

> **The database records the transaction state, but cryptographic evidence determines whether the transaction is actually authorized.**

---

# 🎯 Problem Statement

In a conventional joint bank account system, multiple account holders may be required to approve a transaction.

For example, consider a joint account with four holders:

```text
A ─┐
B ─┤
C ─┤──► Joint Bank Account
D ─┘
