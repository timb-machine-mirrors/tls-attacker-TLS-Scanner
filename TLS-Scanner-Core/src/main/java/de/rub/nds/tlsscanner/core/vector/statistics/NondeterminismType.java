/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

/** Categorizes different types of nondeterministic behavior observed in system responses. */
public enum NondeterminismType {
    /** Nondeterminism that occurs at the connection level */
    CONNECTION,
    /** Nondeterminism that shows heterogeneous response patterns */
    HETEROGENEOUS,
    /** Nondeterminism that exhibits mixed characteristics */
    MIXED
}
