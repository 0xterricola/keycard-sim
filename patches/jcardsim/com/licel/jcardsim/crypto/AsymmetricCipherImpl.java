/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modified by ZKNOX (keycard-sim): ALG_RSA_NOPAD now follows Java Card semantics
 * (input of exactly the modulus length, value < modulus, output of modulus length).
 * The original sized its buffer from BouncyCastle's encrypt input block (k-1 bytes),
 * which rejected the full-length blocks used by keycard-math's RSA squaring trick.
 * Imports point at the BouncyCastle copy shaded inside jcardsim-3.0.5-SNAPSHOT.jar.
 */
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.bouncycastle.crypto.AsymmetricBlockCipher;
import com.licel.jcardsim.bouncycastle.crypto.CipherParameters;
import com.licel.jcardsim.bouncycastle.crypto.InvalidCipherTextException;
import com.licel.jcardsim.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.licel.jcardsim.bouncycastle.crypto.engines.RSAEngine;
import com.licel.jcardsim.bouncycastle.crypto.params.RSAKeyParameters;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.Cipher;

import java.math.BigInteger;

public class AsymmetricCipherImpl extends Cipher {

    byte algorithm;
    AsymmetricBlockCipher engine;
    boolean isInitialized;
    byte[] buffer;
    short bufferPos;

    // ALG_RSA_NOPAD state
    BigInteger modulus;
    BigInteger exponent;
    short modulusLen;

    public AsymmetricCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
        switch (algorithm) {
            case ALG_RSA_NOPAD:
                engine = null;
                break;
            case ALG_RSA_PKCS1:
                engine = new PKCS1Encoding(new RSAEngine());
                break;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof KeyWithParameters)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        CipherParameters params = ((KeyWithParameters) theKey).getParameters();
        if (algorithm == ALG_RSA_NOPAD) {
            if (!(params instanceof RSAKeyParameters)) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            RSAKeyParameters rsa = (RSAKeyParameters) params;
            modulus = rsa.getModulus();
            exponent = rsa.getExponent();
            modulusLen = (short) ((modulus.bitLength() + 7) / 8);
            buffer = JCSystem.makeTransientByteArray(modulusLen, JCSystem.CLEAR_ON_DESELECT);
        } else {
            engine.init(theMode == MODE_ENCRYPT, params);
            buffer = JCSystem.makeTransientByteArray((short) engine.getInputBlockSize(), JCSystem.CLEAR_ON_DESELECT);
        }
        bufferPos = 0;
        isInitialized = true;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        update(inBuff, inOffset, inLength, outBuff, outOffset);

        if (algorithm == ALG_RSA_NOPAD) {
            if (bufferPos != modulusLen || (outBuff.length - outOffset) < modulusLen) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }
            BigInteger x = new BigInteger(1, buffer);
            if (x.compareTo(modulus) >= 0) {
                CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            }
            byte[] y = x.modPow(exponent, modulus).toByteArray();
            Util.arrayFillNonAtomic(outBuff, outOffset, modulusLen, (byte) 0);
            int copy = Math.min(y.length, modulusLen);
            System.arraycopy(y, y.length - copy, outBuff, outOffset + modulusLen - copy, copy);
            bufferPos = 0;
            return modulusLen;
        }

        if ((outBuff.length - outOffset) < engine.getOutputBlockSize()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        try {
            byte[] data = engine.processBlock(buffer, (short) 0, bufferPos);
            Util.arrayCopyNonAtomic(data, (short) 0, outBuff, outOffset, (short) data.length);
            bufferPos = 0;
            return (short) data.length;
        } catch (InvalidCipherTextException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        if (inLength > (buffer.length - bufferPos)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        bufferPos = (short) (bufferPos + Util.arrayCopyNonAtomic(inBuff, inOffset, buffer, bufferPos, inLength));
        return bufferPos;
    }

    public byte getPaddingAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte getCipherAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
