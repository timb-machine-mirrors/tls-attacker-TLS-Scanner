/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.passive;

import de.rub.nds.modifiablevariable.util.ComparableByteArray;
import de.rub.nds.scanner.core.passive.StatExtractor;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import java.util.List;

public class CookieExtractor extends StatExtractor<State, ComparableByteArray> {

    /**
     * Constructs a new CookieExtractor for extracting DTLS cookies from HelloVerifyRequest
     * messages.
     */
    public CookieExtractor() {
        super(TrackableValueType.COOKIE);
    }

    /**
     * Extracts cookies from HelloVerifyRequest messages in the given DTLS state's workflow trace.
     *
     * @param state the state to extract cookies from
     */
    @Override
    public void extract(State state) {
        WorkflowTrace trace = state.getWorkflowTrace();
        List<ProtocolMessage> allReceivedMessages =
                WorkflowTraceResultUtil.getAllReceivedMessagesOfType(
                        trace, ProtocolMessageType.HANDSHAKE);
        for (ProtocolMessage message : allReceivedMessages) {
            if (message instanceof HelloVerifyRequestMessage
                    && ((HelloVerifyRequestMessage) message).getCookie() != null) {
                put(
                        new ComparableByteArray(
                                ((HelloVerifyRequestMessage) message).getCookie().getValue()));
            }
        }
    }
}
