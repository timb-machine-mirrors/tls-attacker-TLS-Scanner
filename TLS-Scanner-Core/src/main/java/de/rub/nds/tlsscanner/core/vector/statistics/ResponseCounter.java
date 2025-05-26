/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;

public class ResponseCounter {

    private final ResponseFingerprint fingerprint;

    private int counter;

    private int total;

    @SuppressWarnings("unused")
    // Default constructor for deserialization
    private ResponseCounter() {
        this.fingerprint = null;
        this.counter = 0;
        this.total = 0;
    }

    public ResponseCounter(ResponseFingerprint fingerprint, int counter, int total) {
        this.fingerprint = fingerprint;
        this.counter = counter;
        this.total = total;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public int getCounter() {
        return counter;
    }

    public int getTotal() {
        return total;
    }

    public void increaseCounterAndTotal() {
        counter++;
        total++;
    }

    public void increaseOnlyTotal() {
        total++;
    }

    public double getProbability() {
        return (double) counter / (double) total;
    }
}
