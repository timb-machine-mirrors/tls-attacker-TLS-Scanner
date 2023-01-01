/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.PskKeyExchangeMode;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class ResumptionProbe extends TlsServerProbe<ConfigSelector, ServerReport> {

    private Set<CipherSuite> supportedSuites;
    private TestResult supportsDtlsCookieExchangeInResumption;
    private TestResult respectsPskModes;
    private TestResult supportsResumption;
    private TestResult supportsSessionTicketResumption;
    private TestResult supportsTls13SessionTicket;
    private TestResult supportsTls13PskDhe;
    private TestResult supportsTls13Psk;
    private TestResult supportsTls13_0rtt;
    private TestResult supportsDtlsCookieExchangeInSessionTicketResumption;

    public ResumptionProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.RESUMPTION, configSelector);
        register(
                TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS,
                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE,
                TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT,
                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK,
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES);
    }

    @Override
    public void executeTest() {
        this.respectsPskModes = TestResults.TRUE;
        if (configSelector.getScannerConfig().getDtlsDelegate().isDTLS()) {
            supportsDtlsCookieExchangeInResumption = getSupportsDtlsCookieExchangeInResumption();

            supportsDtlsCookieExchangeInSessionTicketResumption =
                    getSupportsDtlsCookieExchangeInSessionTicketResumption();
            supportsTls13SessionTicket =
                    supportsTls13PskDhe =
                            supportsTls13Psk = supportsTls13_0rtt = TestResults.NOT_TESTED_YET;
        } else {
            supportsDtlsCookieExchangeInResumption = TestResults.NOT_TESTED_YET;
            supportsDtlsCookieExchangeInSessionTicketResumption = TestResults.NOT_TESTED_YET;
            supportsTls13SessionTicket = getIssuesTls13SessionTicket();
            supportsTls13PskDhe = getSupportsTls13Psk(PskKeyExchangeMode.PSK_DHE_KE);
            supportsTls13Psk = getSupportsTls13Psk(PskKeyExchangeMode.PSK_KE);
            supportsTls13_0rtt = getSupports0rtt();
        }
        supportsResumption = getSupportsSessionResumption();
        supportsSessionTicketResumption = getSupportsSessionTicketResumption();
    }

    private TestResult getSupportsDtlsCookieExchangeInResumption() {
        try {
            Config tlsConfig = configSelector.getBaseConfig();
            tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(tlsConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.DYNAMIC_HANDSHAKE,
                                    tlsConfig.getDefaultRunningMode());
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned()
                    ? TestResults.TRUE
                    : TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13PskDhe");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionResumption() {
        try {
            if (configSelector.foundWorkingConfig()) {
                Config tlsConfig = configSelector.getBaseConfig();
                tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.DYNAMIC_HANDSHAKE,
                                        tlsConfig.getDefaultRunningMode());
                addAlertToTrace(trace);
                trace.addTlsAction(new ResetConnectionAction());
                tlsConfig.setDtlsCookieExchange(
                        supportsDtlsCookieExchangeInResumption == TestResults.TRUE);
                trace.addTlsActions(
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.RESUMPTION,
                                        tlsConfig.getDefaultRunningMode())
                                .getTlsActions());
                State state = new State(tlsConfig, trace);
                executeState(state);
                return state.getWorkflowTrace().executedAsPlanned() == true
                        ? TestResults.TRUE
                        : TestResults.FALSE;
            } else {
                return TestResults.FALSE;
            }
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for SessionResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsDtlsCookieExchangeInSessionTicketResumption() {
        try {
            Config tlsConfig = configSelector.getBaseConfig();
            tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
            tlsConfig.setAddSessionTicketTLSExtension(true);
            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(tlsConfig)
                            .createWorkflowTrace(
                                    WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
            trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
            trace.addTlsAction(
                    new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
            trace.addTlsAction(
                    new ReceiveAction(
                            new NewSessionTicketMessage(),
                            new ChangeCipherSpecMessage(),
                            new FinishedMessage()));
            addAlertToTrace(trace);
            trace.addTlsAction(new ResetConnectionAction());
            trace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));
            trace.addTlsAction(new ReceiveAction(new HelloVerifyRequestMessage()));
            State state = new State(tlsConfig, trace);
            executeState(state);
            return state.getWorkflowTrace().executedAsPlanned()
                    ? TestResults.TRUE
                    : TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error(
                        "Could not test for support for dtls cookie exchange in SessionTicketResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupportsSessionTicketResumption() {
        try {
            if (configSelector.foundWorkingConfig()) {
                Config tlsConfig = configSelector.getBaseConfig();
                tlsConfig.setDefaultClientSupportedCipherSuites(new ArrayList<>(supportedSuites));
                tlsConfig.setAddSessionTicketTLSExtension(true);
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
                trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                trace.addTlsAction(
                        new ReceiveAction(
                                new NewSessionTicketMessage(),
                                new ChangeCipherSpecMessage(),
                                new FinishedMessage()));
                addAlertToTrace(trace);
                trace.addTlsAction(new ResetConnectionAction());
                tlsConfig.setDtlsCookieExchange(
                        supportsDtlsCookieExchangeInResumption == TestResults.TRUE);
                trace.addTlsActions(
                        new WorkflowConfigurationFactory(tlsConfig)
                                .createWorkflowTrace(
                                        WorkflowTraceType.RESUMPTION,
                                        tlsConfig.getDefaultRunningMode())
                                .getTlsActions());
                State state = new State(tlsConfig, trace);
                executeState(state);
                return state.getWorkflowTrace().executedAsPlanned() == true
                        ? TestResults.TRUE
                        : TestResults.FALSE;
            } else {
                return TestResults.FALSE;
            }
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for SessionTicketResumption");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult isKeyShareExtensionNegotiated(State state) {
        List<HandshakeMessage> handshakes =
                WorkflowTraceUtil.getAllReceivedHandshakeMessages(state.getWorkflowTrace());
        List<ServerHelloMessage> hellos =
                handshakes.stream()
                        .filter(message -> message instanceof ServerHelloMessage)
                        .map(message -> (ServerHelloMessage) message)
                        .collect(Collectors.toList());
        if (hellos.size() < 2) {
            return TestResults.COULD_NOT_TEST;
        }
        ServerHelloMessage second = hellos.get(1);
        return second.containsExtension(ExtensionType.KEY_SHARE)
                ? TestResults.TRUE
                : TestResults.FALSE;
    }

    private TestResult getSupportsTls13Psk(PskKeyExchangeMode exchangeMode) {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                List<PskKeyExchangeMode> pskKex = new LinkedList<>();
                pskKex.add(exchangeMode);
                tlsConfig.setPSKKeyExchangeModes(pskKex);
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setAddPreSharedKeyExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_TLS13_PSK);
                // allow an early NewSessionTicket without aborting execution
                tlsConfig.setStopTraceAfterUnexpected(false);
                State state = new State(tlsConfig);
                executeState(state);

                MessageAction lastRcv =
                        (MessageAction) state.getWorkflowTrace().getLastReceivingAction();
                if (lastRcv.executedAsPlanned()) {
                    // Check PSK Modes
                    TestResult keyShareExtensionNegotiated = isKeyShareExtensionNegotiated(state);
                    TestResult keyShareRequired =
                            TestResults.of(exchangeMode.equals(PskKeyExchangeMode.PSK_DHE_KE));
                    if (!keyShareExtensionNegotiated.equals(keyShareRequired)) {
                        if (!TestResults.COULD_NOT_TEST.equals(keyShareExtensionNegotiated)) {
                            respectsPskModes = TestResults.FALSE;
                        }
                    }
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13Psk (" + exchangeMode + "): ", e);
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getSupports0rtt() {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setAddPreSharedKeyExtension(true);
                tlsConfig.setAddEarlyDataExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.FULL_ZERO_RTT);
                State state = new State(tlsConfig);
                executeState(state);

                EncryptedExtensionsMessage encExt =
                        state.getWorkflowTrace()
                                .getLastReceivedMessage(EncryptedExtensionsMessage.class);
                if (encExt != null && encExt.containsExtension(ExtensionType.EARLY_DATA)) {
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13PskDhe");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private TestResult getIssuesTls13SessionTicket() {
        try {
            if (configSelector.foundWorkingTls13Config()) {
                Config tlsConfig = configSelector.getTls13BaseConfig();
                List<PskKeyExchangeMode> pskKex = new LinkedList<>();
                pskKex.add(PskKeyExchangeMode.PSK_DHE_KE);
                pskKex.add(PskKeyExchangeMode.PSK_KE);
                tlsConfig.setPSKKeyExchangeModes(pskKex);
                tlsConfig.setAddPSKKeyExchangeModesExtension(true);
                tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HANDSHAKE);
                State state = new State(tlsConfig);
                state.getWorkflowTrace()
                        .addTlsAction(
                                new ReceiveAction(
                                        tlsConfig.getDefaultClientConnection().getAlias(),
                                        new NewSessionTicketMessage()));
                executeState(state);

                if (WorkflowTraceUtil.didReceiveMessage(
                        HandshakeMessageType.NEW_SESSION_TICKET, state.getWorkflowTrace())) {
                    return TestResults.TRUE;
                }
            }
            return TestResults.FALSE;
        } catch (Exception e) {
            if (e.getCause() instanceof InterruptedException) {
                LOGGER.error("Timeout on " + getProbeName());
                throw new RuntimeException(e);
            } else {
                LOGGER.error("Could not test for support for Tls13SessionTickets");
            }
            return TestResults.ERROR_DURING_TEST;
        }
    }

    private void addAlertToTrace(WorkflowTrace trace) {
        AlertMessage alert = new AlertMessage();
        alert.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        trace.addTlsAction(new SendAction(alert));
    }

    @Override
    protected Requirement getRequirements() {
        return new ProbeRequirement(TlsProbeType.CIPHER_SUITE);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        supportedSuites = report.getSupportedCipherSuites();
        supportedSuites.remove(CipherSuite.TLS_FALLBACK_SCSV);
        supportedSuites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, supportsResumption);
        put(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                supportsSessionTicketResumption);
        put(TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, supportsTls13SessionTicket);
        put(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, supportsTls13PskDhe);
        put(TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT, supportsTls13_0rtt);
        put(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, supportsTls13Psk);
        put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                supportsDtlsCookieExchangeInResumption);
        put(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                supportsDtlsCookieExchangeInSessionTicketResumption);
        put(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES, respectsPskModes);
    }
}
