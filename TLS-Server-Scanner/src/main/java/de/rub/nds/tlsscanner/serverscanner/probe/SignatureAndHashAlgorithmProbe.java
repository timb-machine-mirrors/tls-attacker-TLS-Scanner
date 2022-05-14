/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.function.Predicate;

public class SignatureAndHashAlgorithmProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private List<ProtocolVersion> versions;

    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListSke;
    private List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmListTls13;

    public SignatureAndHashAlgorithmProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.SIGNATURE_AND_HASH, config);
        super.register(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_SKE,
            TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_TLS13);
    }

    @Override
    public void executeTest() {
        Set<SignatureAndHashAlgorithm> supportedSke = new HashSet<>();
        Set<SignatureAndHashAlgorithm> supportedTls13 = new HashSet<>();
        for (ProtocolVersion version : this.versions) {
            if (version.isTLS13())
                supportedTls13.addAll(testForVersion(version, CipherSuite::isTLS13));
            else
                supportedSke.addAll(testForVersion(version, suite -> !suite.isTLS13() && suite.isEphemeral()));
        }
        this.signatureAndHashAlgorithmListSke = new ArrayList<>(supportedSke);
        this.signatureAndHashAlgorithmListTls13 = new ArrayList<>(supportedTls13);
    }

    private Set<SignatureAndHashAlgorithm> testForVersion(ProtocolVersion version, Predicate<CipherSuite> predicate) {
        Set<SignatureAndHashAlgorithm> found = new HashSet<>();
        Set<List<SignatureAndHashAlgorithm>> tested = new HashSet<>();

        Config tlsConfig = version.isTLS13() ? getTls13Config() : this.getBasicConfig();
        tlsConfig.setHighestProtocolVersion(version);
        tlsConfig.getDefaultClientSupportedCipherSuites().removeIf(predicate.negate());

        Queue<List<SignatureAndHashAlgorithm>> testQueue = new LinkedList<>();
        testQueue.add(version.isTLS13() ? SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms()
            : Arrays.asList(SignatureAndHashAlgorithm.values()));

        State state;

        while (!testQueue.isEmpty()) {
            List<SignatureAndHashAlgorithm> testSet = testQueue.poll();
            if (tested.contains(testSet)) {
                continue;
            }
            tested.add(testSet);

            state = testAlgorithms(testSet, tlsConfig);
            if (state != null) {
                SignatureAndHashAlgorithm selected = version.isTLS13() ? getSelectedSignatureAndHashAlgorithmCV(state)
                    : getSelectedSignatureAndHashAlgorithmSke(state);
                if (selected == null) {
                    continue;
                }
                if (!testSet.contains(selected)) {
                    found.add(selected);
                    break;
                }
                // if any new algorithms were found
                if (!found.contains(selected)) {
                    // move selected to end
                    if (testSet.contains(selected)) {
                        List<SignatureAndHashAlgorithm> selectedToEnd = new ArrayList<>(testSet);
                        selectedToEnd.remove(selected);
                        selectedToEnd.add(selected);
                        testQueue.add(selectedToEnd);
                    }
                    // remove possible combinations of selected
                    List<SignatureAndHashAlgorithm> newTestSet = new ArrayList<>(testSet);
                    newTestSet.remove(selected);
                    testQueue.add(newTestSet);
                }
                found.add(selected);
            }
        }
        return found;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmCV(State state) {
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.CERTIFICATE_VERIFY, state.getWorkflowTrace())) {
            HandshakeMessage message = WorkflowTraceUtil.getLastReceivedMessage(HandshakeMessageType.CERTIFICATE_VERIFY,
                state.getWorkflowTrace());
            if (message instanceof CertificateVerifyMessage) {
                CertificateVerifyMessage msg = (CertificateVerifyMessage) message;
                ModifiableByteArray algByte = msg.getSignatureHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                }
            }
        }
        return null;
    }

    private SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithmSke(State state) {
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace())) {
            HandshakeMessage message = WorkflowTraceUtil
                .getLastReceivedMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, state.getWorkflowTrace());
            if (message instanceof ServerKeyExchangeMessage) {
                ServerKeyExchangeMessage msg = (ServerKeyExchangeMessage) message;
                ModifiableByteArray algByte = msg.getSignatureAndHashAlgorithm();
                if (algByte != null) {
                    return SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algByte.getValue());
                }
            }
        }
        return null;
    }

    private State testAlgorithms(List<SignatureAndHashAlgorithm> algorithms, Config config) {
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(algorithms);
        State state = new State(config);
        executeState(state);
        if (state.getWorkflowTrace().executedAsPlanned()) {
            return state;
        } else {
            LOGGER.debug("Did not receive a ServerHello, something went wrong or the Server has some intolerance");
            return null;
        }
    }

    private Config getBasicConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setStopActionsAfterIOException(true);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HELLO);
        tlsConfig.setAddECPointFormatExtension(true);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddRenegotiationInfoExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplemented());

        return tlsConfig;
    }

    private Config getTls13Config() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.values());
        tlsConfig.setDefaultClientKeyShareNamedGroups(NamedGroup.values());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddCertificateStatusRequestExtension(true);
        tlsConfig.setUseFreshRandom(true);
        return tlsConfig;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        ProbeRequirement pReqTls12 = new ProbeRequirement(report).requireProtocolVersions(ProtocolVersion.TLS12);
        ProbeRequirement pReqTls13 = new ProbeRequirement(report).requireProtocolVersions(ProtocolVersion.TLS13);
        ProbeRequirement pReqDtls12 = new ProbeRequirement(report).requireProtocolVersions(ProtocolVersion.DTLS12);
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.PROTOCOL_VERSION).orRequirement(pReqDtls12,
            pReqTls12, pReqTls13);
    }

    @SuppressWarnings("unchecked")
	@Override
    public void adjustConfig(ServerReport report) {
        this.versions = new ArrayList<>();
        for (ProtocolVersion version : ((ListResult<ProtocolVersion>) report.getResultMap().get(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS.name())).getList()) {
            if (version.equals(ProtocolVersion.DTLS12) || version.equals(ProtocolVersion.TLS12) || version.isTLS13()) {
                versions.add(version);
            }
        }
    }

    @Override
    public SignatureAndHashAlgorithmProbe getCouldNotExecuteResult() {
        this.signatureAndHashAlgorithmListSke = null;
        this.signatureAndHashAlgorithmListTls13 = null;
        return this;
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_SKE,
            new ListResult<SignatureAndHashAlgorithm>(this.signatureAndHashAlgorithmListSke,
                "SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_SKE"));
        super.put(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_TLS13,
            new ListResult<SignatureAndHashAlgorithm>(this.signatureAndHashAlgorithmListTls13,
                "SUPPORTED_SIGNATUREANDHASH_ALGORITHMS_TLS13"));
    }
}
