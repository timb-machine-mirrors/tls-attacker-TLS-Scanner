/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.BaseRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class DtlsFragmentationProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private TestResult supportsDirectly;
    private TestResult supportsDirectlyIndPackets;
    private TestResult supportsAfterCookieExchange;
    private TestResult supportsAfterCookieExchangeIndPackets;
    private TestResult supportsWithExtension;
    private TestResult supportsWithExtensionIndPackets;

    private static final int INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN = 200;

    public DtlsFragmentationProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.DTLS_FRAGMENTATION, configSelector);
        register(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION,
            TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION,
            TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
            TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION);
    }

    @Override
    public void executeTest() {
        supportsDirectly = supportsFragmentationDirectly(false);
        supportsDirectlyIndPackets = supportsFragmentationDirectly(true);
        supportsAfterCookieExchange = supportsFragmentationAfterCookieExchange(false);
        supportsAfterCookieExchangeIndPackets = supportsFragmentationAfterCookieExchange(true);
        supportsWithExtension = supportsFragmentationWithExtension(false);
        supportsWithExtensionIndPackets = supportsFragmentationWithExtension(true);
    }

    private TestResult supportsFragmentationDirectly(boolean individualTransportPackets) {
        Config config = configSelector.getBaseConfig();
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        config.setDtlsMaximumFragmentLength(150);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        State state = new State(config);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO_DONE, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationAfterCookieExchange(boolean individualTransportPackets) {
        Config config = configSelector.getBaseConfig();
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    private TestResult supportsFragmentationWithExtension(boolean individualTransportPackets) {
        Config config = configSelector.getBaseConfig();
        config.setAddMaxFragmentLengthExtension(true);
        config.setDefaultMaxFragmentLength(MaxFragmentLength.TWO_11);
        if (individualTransportPackets) {
            config.setCreateIndividualTransportPackets(true);
            config.setIndividualTransportPacketCooldown(INDIVIDUAL_TRANSPORT_PACKET_COOLDOWN);
        }

        WorkflowTrace trace = new WorkflowConfigurationFactory(config)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        SendDynamicClientKeyExchangeAction action = new SendDynamicClientKeyExchangeAction();
        action.setFragments(new DtlsHandshakeMessageFragment(config, 20), new DtlsHandshakeMessageFragment(config, 20));
        trace.addTlsAction(action);
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(config), new FinishedMessage(config)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage(config)));

        State state = new State(config, trace);
        executeState(state);
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, state.getWorkflowTrace())) {
            return TestResults.TRUE;
        } else {
            return TestResults.FALSE;
        }
    }

    @Override
    protected Requirement getRequirements() {
        return BaseRequirement.NO_REQUIREMENT;
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (supportsDirectly == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.TRUE);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsAfterCookieExchange == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsWithExtension == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.PARTIALLY);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.TRUE);
        } else {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION, TestResults.FALSE);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION, TestResults.FALSE);
        }

        if (supportsDirectlyIndPackets == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.TRUE);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsAfterCookieExchangeIndPackets == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.PARTIALLY);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
        } else if (supportsWithExtensionIndPackets == TestResults.TRUE) {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.PARTIALLY);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.TRUE);
        } else {
            put(TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS, TestResults.FALSE);
            put(TlsAnalyzedProperty.DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION, TestResults.FALSE);
        }
    }
}
