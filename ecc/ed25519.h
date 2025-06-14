/**
 * @file ed25519.h
 * @brief Ed25519 elliptic curve (constant-time implementation)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.2
 **/

#ifndef _ED25519_H
#define _ED25519_H

//Dependencies
#include "core/crypto.h"
#include "ecc/eddsa.h"
#include "hash/sha512.h"

//Length of Ed25519 private keys
#define ED25519_PRIVATE_KEY_LEN 32
//Length of Ed25519 public keys
#define ED25519_PUBLIC_KEY_LEN 32
//Length of Ed25519 signatures
#define ED25519_SIGNATURE_LEN 64

//Ed25519ph flag
#define ED25519_PH_FLAG 1
//Prehash function output size
#define ED25519_PH_SIZE 64

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Extended point representation
 **/

typedef struct
{
   int32_t x[9];
   int32_t y[9];
   int32_t z[9];
   int32_t t[9];
} Ed25519Point;


/**
 * @brief Working state (scalar multiplication)
 **/

typedef struct
{
   Ed25519Point u;
   Ed25519Point v;
   int32_t a[9];
   int32_t b[9];
   int32_t c[9];
   int32_t d[9];
   int32_t e[9];
   int32_t f[9];
   int32_t g[9];
   int32_t h[9];
} Ed25519SubState;


/**
 * @brief Working state (public key generation)
 **/

typedef struct
{
   Sha512Context sha512Context;
   uint8_t s[64];
   Ed25519Point a;
   Ed25519SubState subState;
} Ed25519GeneratePublicKeyState;


/**
 * @brief Working state (signature generation)
 **/

typedef struct
{
   Sha512Context sha512Context;
   uint8_t h[64];
   uint8_t k[64];
   uint8_t p[32];
   uint8_t r[32];
   uint8_t s[32];
   Ed25519Point a;
   Ed25519SubState subState;
} Ed25519GenerateSignatureState;


/**
 * @brief Working state (signature verification)
 **/

typedef struct
{
   Sha512Context sha512Context;
   uint8_t k[64];
   uint8_t p[32];
   uint8_t r[32];
   uint8_t s[32];
   Ed25519Point a;
   Ed25519SubState subState;
} Ed25519VerifySignatureState;


//Ed25519 related functions
error_t ed25519GenerateKeyPair(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey, uint8_t *publicKey);

error_t ed25519GeneratePrivateKey(const PrngAlgo *prngAlgo, void *prngContext,
   uint8_t *privateKey);

error_t ed25519GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey);

error_t ed25519GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed25519GenerateSignatureEx(const uint8_t *privateKey,
   const uint8_t *publicKey, const DataChunk *message, uint_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

error_t ed25519VerifySignature(const uint8_t *publicKey, const void *message,
   size_t messageLen, const void *context, uint8_t contextLen, uint8_t flag,
   const uint8_t *signature);

error_t ed25519VerifySignatureEx(const uint8_t *publicKey,
   const DataChunk *message, uint_t messageLen, const void *context,
   uint8_t contextLen, uint8_t flag, const uint8_t *signature);

void ed25519Mul(Ed25519SubState *state, Ed25519Point *r, const uint8_t *k,
   const Ed25519Point *p);

void ed25519TwinMul(Ed25519SubState *state, Ed25519Point *r, const uint8_t *k1,
   const Ed25519Point *p, const uint8_t *k2, const Ed25519Point *q);

void ed25519Add(Ed25519SubState *state, Ed25519Point *r, const Ed25519Point *p,
   const Ed25519Point *q);

void ed25519Double(Ed25519SubState *state, Ed25519Point *r,
   const Ed25519Point *p);

void ed25519Encode(Ed25519Point *p, uint8_t *data);
uint32_t ed25519Decode(Ed25519Point *p, const uint8_t *data);

void ed25519RedInt(uint8_t *r, const uint8_t *a);

void ed25519AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);
uint8_t ed25519SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint_t n);

void ed25519MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
   const uint8_t *b, uint_t n);

void ed25519CopyInt(uint8_t *a, const uint8_t *b, uint_t n);

void ed25519SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
   uint8_t c, uint_t n);

uint8_t ed25519CompInt(const uint8_t *a, const uint8_t *b, uint_t n);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
