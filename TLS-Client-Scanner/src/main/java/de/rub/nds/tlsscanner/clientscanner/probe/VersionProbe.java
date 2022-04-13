/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionProbe extends TlsProbe<ClientScannerConfig, ClientReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<CipherSuite> clientAdvertisedCipherSuites = null;
    private List<ProtocolVersion> supportedProtocolVersions;
    private List<ProtocolVersion> unsupportedProtocolVersions;

    public VersionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.PROTOCOL_VERSION, scannerConfig);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_SSL_2);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_SSL_3);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_TLS_1_0);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_TLS_1_1);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_TLS_1_2);
        super.properties.add(TlsAnalyzedProperty.SUPPORTS_TLS_1_3);
    }

    protected Config getTls13Config() {
        Config config = getScannerConfig().createConfig();
        // no need to set CipherSuites; this is done in executeTest
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        return config;
    }

    @Override
    public void executeTest() {
        ProtocolVersion[] versionsToTest = { ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11,
            ProtocolVersion.TLS12, ProtocolVersion.TLS13 };
        this.supportedProtocolVersions = new LinkedList<>();
        this.unsupportedProtocolVersions = new LinkedList<>();
        for (ProtocolVersion version : versionsToTest) {
            LOGGER.debug("Testing version {}", version);
            Config config;
            if (version.isTLS13()) {
                config = getTls13Config();
            } else {
                config = getScannerConfig().createConfig();
            }
            List<CipherSuite> suitableCiphersuites = clientAdvertisedCipherSuites.stream()
                .filter(suite -> suite.isSupportedInProtocol(version)).collect(Collectors.toList());
            if (suitableCiphersuites.size() == 0) {
                CipherSuite fallback = clientAdvertisedCipherSuites.get(0);
                LOGGER.warn("No suitable cipher suite found for {}. Using {} instead.", version, fallback);
                suitableCiphersuites.add(fallback);
            }

            config.setDefaultServerSupportedCipherSuites(suitableCiphersuites);
            config.setDefaultSelectedCipherSuite(suitableCiphersuites.get(0));
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
            // confirm success
            State state = new State(config, trace);
            executeState(state);
            if (state.getWorkflowTrace().executedAsPlanned())
                this.supportedProtocolVersions.add(version);
            else
                this.unsupportedProtocolVersions.add(version);
        }
    }

    @Override
    public VersionProbe getCouldNotExecuteResult() {
        this.supportedProtocolVersions = this.unsupportedProtocolVersions = null;
        return this;
    }

    @Override
    public void adjustConfig(ClientReport report) {
        this.clientAdvertisedCipherSuites = report.getAdvertisedCipherSuites();
    }

    @Override
    protected Requirement getRequirements(ClientReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.BASIC);
    }

    @Override
    protected void mergeData(ClientReport report) {
        if (supportedProtocolVersions != null) {
            report.setSupportedVersions(supportedProtocolVersions);

            for (ProtocolVersion version : supportedProtocolVersions) {
                if (version == ProtocolVersion.SSL2) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.TRUE);
                }
                if (version == ProtocolVersion.SSL3) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS10) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS11) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS12) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE);
                }
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE);
                }
            }

            for (ProtocolVersion version : unsupportedProtocolVersions) {
                if (version == ProtocolVersion.SSL2) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.FALSE);
                }
                if (version == ProtocolVersion.SSL3) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS10) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS11) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS12) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.FALSE);
                }
                if (version == ProtocolVersion.TLS13) {
                    report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.FALSE);
                }
            }
        } else {
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_2, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_SSL_3, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.COULD_NOT_TEST);
            report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.COULD_NOT_TEST);
        }
    }

}
