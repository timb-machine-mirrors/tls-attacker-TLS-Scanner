/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.StarttlsConfigurationResult;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class StarttlsConfigurationProbe extends TlsProbe {

    private Set<CipherSuite> supportedSuites;

    public StarttlsConfigurationProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.STARTTLS_CONFIGURATION, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult vulnerable = TestResult.FALSE;
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
            //TODO: Workflow currently does not issue the clients CAPA-command
            WorkflowConfigurationFactory configFactory = new WorkflowConfigurationFactory(tlsConfig);
            WorkflowTrace trace = configFactory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE,
                    RunningModeType.CLIENT);
            State state = new State(tlsConfig, trace);
            executeState(state);

            //Check if Server's capabilities offered a plain login.
            List<ServerCapability> offerPlainLogin = ServerCapability.getPlainLogin();
            List<ServerCapability> capabilities = state.getTlsContext().getServerCapabilities();
            if(Collections.disjoint(offerPlainLogin, capabilities))
                vulnerable = TestResult.FALSE;
            else
                vulnerable = TestResult.TRUE;

            return new StarttlsConfigurationResult(vulnerable);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new StarttlsConfigurationResult(TestResult.ERROR_DURING_TEST);
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
    public ProbeResult getCouldNotExecuteResult() {
        return new StarttlsConfigurationResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {

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
