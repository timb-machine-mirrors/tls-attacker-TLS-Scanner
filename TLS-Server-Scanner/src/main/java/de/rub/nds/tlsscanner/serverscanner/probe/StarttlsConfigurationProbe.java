/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import com.google.common.base.Ascii;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.starttls.ServerCapability;
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolHandler;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.action.starttls.StarttlsActionFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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
            StarttlsType type = tlsConfig.getStarttlsType();
            tlsConfig.setQuickReceive(true);
            List<CipherSuite> ciphersuites = new LinkedList<>();
            ciphersuites.addAll(supportedSuites);
            tlsConfig.setDefaultClientSupportedCipherSuites(ciphersuites);
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

            // Create a WorkflowTrace that requests the servers capabilities.
            WorkflowTrace workflowTrace = new WorkflowTrace();
            workflowTrace.addTlsAction(StarttlsActionFactory.createServerGreetingAction(tlsConfig,
                tlsConfig.getDefaultClientConnection(), ConnectionEndType.SERVER, "US-ASCII"));
            workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(tlsConfig,
                tlsConfig.getDefaultClientConnection(), ConnectionEndType.CLIENT, StarttlsCommandType.C_CAPA,
                "US-ASCII"));
            workflowTrace.addTlsAction(StarttlsActionFactory.createServerCapabilitiesAction(tlsConfig,
                tlsConfig.getDefaultClientConnection(), ConnectionEndType.SERVER, "US-ASCII"));
            workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(tlsConfig,
                tlsConfig.getDefaultClientConnection(), ConnectionEndType.CLIENT, StarttlsCommandType.C_STARTTLS,
                "US-ASCII"));
            workflowTrace.addTlsAction(StarttlsActionFactory.createIssueStarttlsCommandAction(tlsConfig,
                tlsConfig.getDefaultClientConnection(), ConnectionEndType.SERVER, StarttlsCommandType.S_STARTTLS,
                "US-ASCII"));

            State state = new State(tlsConfig, workflowTrace);
            executeState(state);

            StarttlsProtocolHandler handler = StarttlsProtocolFactory.getProtocol(type);
            List<ServerCapability> capabilities = state.getTlsContext().getServerCapabilities();
            vulnerable = TestResult.FALSE;
            String text = "";
            for (ServerCapability capa : capabilities) {
                text += capa.getName() + ",";
                if (handler.offersPlainLogin(capa.getName()))
                    vulnerable = TestResult.TRUE;
            }

            return new StarttlsConfigurationResult(vulnerable, text);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new StarttlsConfigurationResult(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        // TODO FTP currently not supported
        boolean result = scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE
            && scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.FTP;

        return result;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new StarttlsConfigurationResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportedSuites = report.getCipherSuites();
    }

    /**
     * Used to run the probe with empty CS list if we already know versions before TLS 1.3 are not supported, to avoid
     * stalling of probes that depend on this one
     */
    private boolean supportsOnlyTls13(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.FALSE
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.FALSE;
    }
}
