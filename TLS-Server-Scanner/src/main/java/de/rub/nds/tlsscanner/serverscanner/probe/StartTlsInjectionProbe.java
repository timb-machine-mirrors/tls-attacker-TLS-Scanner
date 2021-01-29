/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import static de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe.LOGGER;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.StartTlsInjectionResult;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class StartTlsInjectionProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;

    public StartTlsInjectionProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.STARTTLS_INJECTION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult vulnerable;
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> ciphersuites = new LinkedList<>();
            ciphersuites.addAll(supportedSuites);
            tlsConfig.setDefaultClientSupportedCiphersuites(ciphersuites);
            tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS12);
            tlsConfig.setEnforceSettings(false);
            tlsConfig.setEarlyStop(true);
            tlsConfig.setStopReceivingAfterFatal(true);
            tlsConfig.setStopActionsAfterFatal(true);
            tlsConfig.setAddECPointFormatExtension(true);
            tlsConfig.setAddEllipticCurveExtension(true);
            tlsConfig.setAddServerNameIndicationExtension(true);
            tlsConfig.setAddRenegotiationInfoExtension(true);
            tlsConfig.setStopActionsAfterIOException(true);
            tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
            tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
            tlsConfig.getDefaultClientNamedGroups().remove(NamedGroup.ECDH_X25519);
            WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
            WorkflowTrace trace = configFactory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE,
                    RunningModeType.CLIENT);
            State state = new State(tlsConfig, trace);
            // Find last executed ascii send action
            SendAsciiAction sendAction = null;
            for (TlsAction action : trace.getTlsActions()) {
                if (action instanceof SendAsciiAction) {
                    sendAction = (SendAsciiAction) action;
                }
            }
            if (sendAction == null) {
                throw new RuntimeException("Could not find last SendAscii action in WorkflowTrace");
            }
            String injectionCommand;
            String retryCommand;
            switch (scannerConfig.getStarttlsDelegate().getStarttlsType()) {
                case SMTP:
                    injectionCommand = "EHLO scanner.example.com\r\n";
                    retryCommand = "QUIT";
                    break;
                case POP3:
                    injectionCommand = "CAPA\r\n";
                    retryCommand = "QUIT";
                    break;
                case IMAP:
                    injectionCommand = "inj CAPABILITY\r\n";
                    retryCommand = "B LOGOUT";
                    break;
                default:
                    throw new RuntimeException("Injection not implemented");
            }
            sendAction.setAsciiText(sendAction.getAsciiText() + injectionCommand);
            trace.addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                    new ApplicationMessage(tlsConfig)));
            executeState(state);
            byte[] lastHandledApplicationMessageData = state.getTlsContext().getLastHandledApplicationMessageData();
            if (lastHandledApplicationMessageData != null) {
                String asciiMessage = new String(lastHandledApplicationMessageData, "US-ASCII");
                if (scannerConfig.getStarttlsDelegate().getStarttlsType() == StarttlsType.IMAP) {
                    if (asciiMessage.contains("inj")) {
                        vulnerable = TestResult.TRUE;
                    } else {
                        vulnerable = TestResult.FALSE;
                    }
                } else {
                    vulnerable = TestResult.TRUE;
                }
            } else {
                // See if injected command is evaluated after another command
                trace.addTlsAction(new SendAsciiAction(retryCommand));// TODO:
                                                                      // Send as
                                                                      // ApplicationData
                trace.addTlsAction(new ReceiveAction(tlsConfig.getDefaultClientConnection().getAlias(),
                        new ApplicationMessage(tlsConfig)));
                State retryState = new State(tlsConfig, trace);
                executeState(retryState);
                byte[] lastHandledRetryApplicationMessageData = retryState.getTlsContext()
                        .getLastHandledApplicationMessageData();
                if (lastHandledRetryApplicationMessageData == null)
                    vulnerable = TestResult.FALSE;
                else {
                    String retryAsciiMessage = new String(lastHandledRetryApplicationMessageData, "US-ASCII");
                    switch (scannerConfig.getStarttlsDelegate().getStarttlsType()) {
                        case IMAP:
                            if (retryAsciiMessage.contains("inj"))
                                vulnerable = TestResult.TRUE;
                            else
                                vulnerable = TestResult.FALSE;
                            break;
                        case POP3:
                            if (retryAsciiMessage.contains("STLS") || retryAsciiMessage.contains("USER")
                                    || retryAsciiMessage.contains("SASL") || retryAsciiMessage.contains("CAPA")
                                    || retryAsciiMessage.contains("UIDL") || retryAsciiMessage.contains("PIPELINING"))
                                vulnerable = TestResult.TRUE;
                            else
                                vulnerable = TestResult.FALSE;
                            break;
                        case SMTP:
                            if (retryAsciiMessage.contains("250"))
                                vulnerable = TestResult.TRUE;
                            else
                                vulnerable = TestResult.FALSE;
                        default:
                            vulnerable = TestResult.COULD_NOT_TEST;
                    }
                }
            }
            return new StartTlsInjectionResult(vulnerable);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new StartTlsInjectionResult(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        // TODO FTP currently not supported
        return report.getCipherSuites() != null && report.getCipherSuites().size() > 0 && !supportsOnlyTls13(report)
                && scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE
                && scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.FTP;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new StartTlsInjectionResult(TestResult.COULD_NOT_TEST);
    }

    /**
     * Used to run the probe with empty CS list if we already know versions
     * before TLS 1.3 are not supported, to avoid stalling of probes that depend
     * on this one
     */
    private boolean supportsOnlyTls13(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.FALSE
                && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.FALSE;
    }
}
