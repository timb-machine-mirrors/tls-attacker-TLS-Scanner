/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

public class VeryShortPaddingGenerator extends PaddingVectorGenerator {

    /** Default length of the encrypted data (app + mac + padding) */
    static final int DEFAULT_CIPHERTEXT_LENGTH = 80;

    /** Default padding length for the construction of modified encrypted plaintexts */
    static final int DEFAULT_PADDING_LENGTH = 4;

    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        vectorList.addAll(createOnlyPaddingVectors(suite, version));
        vectorList.addAll(createClassicModifiedPadding(suite, version));
        return vectorList;
    }

    List<PaddingVector> createOnlyPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        byte[] plain = createPaddingBytes(DEFAULT_CIPHERTEXT_LENGTH - 1);
        vectorList.add(
                createVectorWithPlainData(
                        "Plain XF (0xXF=#padding bytes)", "PlainOnlyPadding", plain));
        plain =
                new byte[] {
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                    (byte) 255,
                };
        vectorList.add(createVectorWithPlainData("Plain FF", "PlainTooMuchPadding", plain));
        return vectorList;
    }

    List<PaddingVector> createClassicModifiedPadding(CipherSuite suite, ProtocolVersion version) {
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getMacLength();
        int paddingValue = DEFAULT_CIPHERTEXT_LENGTH - macSize - 1;
        int applicationLength = 0;
        List<PaddingVector> vectorList =
                createClassicModifiedPaddingWithValidMAC(applicationLength, paddingValue);
        vectorList.addAll(
                createClassicModifiedPaddingWithInvalidMAC(applicationLength, paddingValue));

        return vectorList;
    }

    private List<PaddingVector> createClassicModifiedPaddingWithValidMAC(
            int applicationLength, int paddingValue) {
        List<PaddingVector> vectorList = new LinkedList<>();
        // valid mac
        byte[] padding = createPaddingBytes(paddingValue);
        padding[0] ^= 0x80; // flip first padding byte highest bit
        vectorList.add(
                new TripleVector(
                        "InvPadValMac-[0]-" + applicationLength + "-" + paddingValue,
                        "InvPadValMac",
                        new ByteArrayExplicitValueModification(new byte[applicationLength]),
                        null,
                        new ByteArrayExplicitValueModification(padding)));
        return vectorList;
    }

    private List<PaddingVector> createClassicModifiedPaddingWithInvalidMAC(
            int applicationLength, int paddingValue) {
        List<PaddingVector> vectorList = new LinkedList<>();
        // invalid mac
        byte[] padding = createPaddingBytes(paddingValue);
        vectorList.add(
                new TripleVector(
                        "ValPadInvMac-[0]-" + applicationLength + "-" + paddingValue,
                        "valPadInvMac",
                        new ByteArrayExplicitValueModification(new byte[applicationLength]),
                        new ByteArrayXorModification(new byte[] {0x01}, 0),
                        new ByteArrayExplicitValueModification(padding)));
        return vectorList;
    }

    List<ByteArrayXorModification> createFlippedModifications(int byteLength) {
        List<ByteArrayXorModification> modificationList = new LinkedList<>();
        modificationList.add(
                new ByteArrayXorModification(new byte[] {0x01}, byteLength - 1)); // Last
        // Byte / lowest bit
        modificationList.add(
                new ByteArrayXorModification(new byte[] {0x08}, byteLength / 2)); // Some
        // Byte / middle bit
        modificationList.add(new ByteArrayXorModification(new byte[] {(byte) 0x80}, 0)); // first
        // Byte / highest bit
        return modificationList;
    }

    private PaddingVector createVectorWithPlainData(String name, String identifier, byte[] plain) {
        return new PlainPaddingVector(
                name, identifier, new ByteArrayExplicitValueModification(plain));
    }
}
