/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.scanner.core.probe.requirements.OrRequirement;
import de.rub.nds.scanner.core.probe.requirements.ProbeRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.requirements.PropertyTrueRequirement;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class NamedGroupsProbe extends TlsClientProbe {

    // can only be evaluated if client lists them
    private final List<NamedGroup> ffdheToTest = new LinkedList<>();

    private final List<NamedGroup> advertisedKeyShareGroups = new LinkedList<>();
    private List<CipherSuite> supportedDheCipherSuites;
    private List<CipherSuite> supportedEcdheCipherSuites;
    private List<CipherSuite> supportedTls13CipherSuites;

    private final List<NamedGroup> supportedNamedGroups = new LinkedList<>();
    private final List<NamedGroup> supportedTls13NamedGroups = new LinkedList<>();

    public NamedGroupsProbe(ParallelExecutor parallelExecutor, ClientScannerConfig scannerConfig) {
        super(parallelExecutor, TlsProbeType.NAMED_GROUPS, scannerConfig);
    }

    @Override
    protected void mergeData(ClientReport report) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void executeTest() {
        if (!supportedDheCipherSuites.isEmpty() && !ffdheToTest.isEmpty()) {
            supportedNamedGroups.addAll(getSupportedGroups(ffdheToTest, supportedDheCipherSuites));
        }
        if (!supportedEcdheCipherSuites.isEmpty()) {
            supportedNamedGroups.addAll(
                    getSupportedGroups(getCurvesToTest(), supportedEcdheCipherSuites));
        }
        if (!supportedTls13CipherSuites.isEmpty()) {
            supportedTls13NamedGroups.addAll(
                    getSupportedGroupsTls13(ffdheToTest, supportedDheCipherSuites));
        }
    }

    private List<NamedGroup> getCurvesToTest() {
        return NamedGroup.getImplemented().stream()
                .filter(NamedGroup::isCurve)
                .filter(Predicate.not(NamedGroup::isGost))
                .collect(Collectors.toList());
    }

    private List<NamedGroup> getSupportedGroups(
            List<NamedGroup> baseList, List<CipherSuite> cipherSuites) {
        List<State> statesToExecute = new LinkedList<>();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : baseList) {
            Config config = scannerConfig.createConfig();
            setSharedConfigFields(config, group, cipherSuites);
            statesToExecute.add(new State(config));
        }
        executeState(statesToExecute);
        for (State executedState : statesToExecute) {
            if (WorkflowTraceUtil.didReceiveMessage(
                    HandshakeMessageType.CLIENT_KEY_EXCHANGE, executedState.getWorkflowTrace())) {
                supportedGroups.add(executedState.getConfig().getDefaultSelectedNamedGroup());
            }
        }
        return supportedGroups;
    }

    private List<NamedGroup> getSupportedGroupsTls13(
            List<NamedGroup> baseList, List<CipherSuite> cipherSuites) {
        List<State> statesToExecute = new LinkedList<>();
        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : baseList) {
            Config config = scannerConfig.createConfig();
            setSharedConfigFields(config, group, cipherSuites);
            WorkflowTrace workflowTrace =
                    new WorkflowConfigurationFactory(config)
                            .createDynamicHelloWorkflow(config.getDefaultServerConnection());
            if (advertisedKeyShareGroups.contains(group)) {
                workflowTrace.addTlsAction(new ReceiveAction(new FinishedMessage()));
            } else {
                ServerHelloMessage serverHello =
                        workflowTrace.getFirstSendMessage(ServerHelloMessage.class);
                serverHello.setAutoSetHelloRetryModeInKeyShare(true);
                serverHello.setRandom(
                        Modifiable.explicit(ServerHelloMessage.getHelloRetryRequestRandom()));
                workflowTrace.addTlsAction(new ReceiveAction(new ClientHelloMessage()));
            }
            statesToExecute.add(new State(config, workflowTrace));
        }
        executeState(statesToExecute);
        for (State executedState : statesToExecute) {
            NamedGroup testedGroup = executedState.getConfig().getDefaultSelectedNamedGroup();
            if (advertisedKeyShareGroups.contains(testedGroup)
                    && WorkflowTraceUtil.didReceiveMessage(
                            HandshakeMessageType.FINISHED, executedState.getWorkflowTrace())) {
                supportedGroups.add(testedGroup);
            } else if (!advertisedKeyShareGroups.contains(testedGroup)) {
                List<HandshakeMessage> handshakeMessages =
                        WorkflowTraceUtil.getAllReceivedHandshakeMessages(
                                executedState.getWorkflowTrace());
                if (handshakeMessages.stream().filter(ClientHelloMessage.class::isInstance).count()
                        > 1) {
                    ClientHelloMessage updatedClientHello =
                            (ClientHelloMessage)
                                    WorkflowTraceUtil.getLastReceivedMessage(
                                            HandshakeMessageType.CLIENT_HELLO,
                                            executedState.getWorkflowTrace());
                    if (updatedClientHello
                            .getExtension(KeyShareExtensionMessage.class)
                            .getKeyShareList()
                            .stream()
                            .map(KeyShareEntry::getGroupConfig)
                            .anyMatch(testedGroup::equals)) {
                        supportedGroups.add(testedGroup);
                    }
                }
            }
        }
        return supportedGroups;
    }

    public void setSharedConfigFields(
            Config config, NamedGroup group, List<CipherSuite> cipherSuites) {
        config.setDefaultSelectedNamedGroup(group);
        config.setDefaultServerNamedGroups(group);
        config.setDefaultServerSupportedCipherSuites(cipherSuites);
        config.setDefaultSelectedCipherSuite(cipherSuites.get(0));
        config.setEnforceSettings(true);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        report.getClientAdvertisedNamedGroupsList().stream()
                .filter(NamedGroup::isDhGroup)
                .forEach(ffdheToTest::add);
        report.getClientAdvertisedKeyShareNamedGroupsList().forEach(advertisedKeyShareGroups::add);
        supportedTls13CipherSuites =
                report.getSupportedCipherSuites().stream()
                        .filter(CipherSuite::isTLS13)
                        .collect(Collectors.toList());
        supportedDheCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.DHE_DSS, KeyExchangeAlgorithm.DHE_RSA);
        supportedEcdheCipherSuites =
                report.getSupportedCipherSuitesWithKeyExchange(
                        KeyExchangeAlgorithm.ECDHE_ECDSA, KeyExchangeAlgorithm.ECDHE_RSA);
    }

    @Override
    public Requirement<ClientReport> getRequirements() {
        return new ProbeRequirement<ClientReport>(TlsProbeType.BASIC)
                .and(new ProbeRequirement<>(TlsProbeType.CIPHER_SUITE))
                .and(
                        new OrRequirement<ClientReport>(
                                List.of(
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_DHE),
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_ECDHE),
                                        new PropertyTrueRequirement<>(
                                                TlsAnalyzedProperty.SUPPORTS_TLS_1_3))));
    }
}
