/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Objects;

public class TripleVector extends PaddingVector {

    private final VariableModification cleanModification;
    private final VariableModification macModification;
    private final VariableModification paddingModification;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private TripleVector() {
        super(null, null);
        this.cleanModification = null;
        this.macModification = null;
        this.paddingModification = null;
    }

    public TripleVector(
            String name,
            String identifier,
            VariableModification cleanModification,
            VariableModification macModification,
            VariableModification paddingModification) {
        super(name, identifier);
        this.cleanModification = cleanModification;
        this.macModification = macModification;
        this.paddingModification = paddingModification;
    }

    @Override
    public Record createRecord() {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        if (paddingModification != null) {
            byteArray.setModifications(paddingModification);
        }
        r.getComputations().setPadding(byteArray);
        byteArray = new ModifiableByteArray();
        if (cleanModification != null) {
            byteArray.setModifications(cleanModification);
        }
        r.setCleanProtocolMessageBytes(byteArray);
        byteArray = new ModifiableByteArray();
        if (macModification != null) {
            byteArray.setModifications(macModification);
        }
        r.getComputations().setMac(byteArray);
        return r;
    }

    @Override
    public int getRecordLength(
            CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength) {
        Record r = createRecord();
        int macLength =
                AlgorithmResolver.getMacAlgorithm(testedVersion, testedSuite).getMacLength();

        r.setCleanProtocolMessageBytes(new byte[appDataLength]);
        r.getComputations().setMac(new byte[macLength]);
        int paddingLength =
                AlgorithmResolver.getCipher(testedSuite).getBlocksize()
                        - ((r.getCleanProtocolMessageBytes().getValue().length
                                        + r.getComputations().getMac().getValue().length)
                                % AlgorithmResolver.getCipher(testedSuite).getBlocksize());

        r.getComputations().setPadding(new byte[paddingLength]);
        return ArrayConverter.concatenate(
                        r.getCleanProtocolMessageBytes().getValue(),
                        r.getComputations().getMac().getValue(),
                        r.getComputations().getPadding().getValue())
                .length;
    }

    public VariableModification getPaddingModification() {
        return paddingModification;
    }

    public VariableModification getCleanModification() {
        return cleanModification;
    }

    public VariableModification getMacModification() {
        return macModification;
    }

    @Override
    public String toString() {
        return ""
                + name
                + "{"
                + "cleanModification="
                + cleanModification
                + ", macModification="
                + macModification
                + ", paddingModification="
                + paddingModification
                + '}';
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.cleanModification);
        hash = 23 * hash + Objects.hashCode(this.macModification);
        hash = 23 * hash + Objects.hashCode(this.paddingModification);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final TripleVector other = (TripleVector) obj;
        if (!Objects.equals(this.cleanModification, other.cleanModification)) {
            return false;
        }
        if (!Objects.equals(this.macModification, other.macModification)) {
            return false;
        }
        return Objects.equals(this.paddingModification, other.paddingModification);
    }
}
