/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAsciiAction;
import de.rub.nds.tlsattacker.core.workflow.action.StarttlsActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.StarttlsMessageFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.StarttlsPlainLoginResult;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class StarttlsPlainLoginProbe extends TlsProbe {

    public StarttlsPlainLoginProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.STARTTLS_PLAIN_LOGIN, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            TestResult vulnerable;
            Config tlsConfig = getScannerConfig().createConfig();
            tlsConfig.setQuickReceive(true);
            tlsConfig.setEarlyStop(true);
            switch (tlsConfig.getStarttlsType()) {
                case IMAP:
                    vulnerable = executeIMAP(tlsConfig);
                    break;
                case POP3:
                    vulnerable = executePOP3(tlsConfig);
                    break;
                case SMTP:
                    vulnerable = executeSMTP(tlsConfig);
                    break;
                default:
                    throw new RuntimeException(getProbeName() + " not implemented for Starttls type \""
                            + tlsConfig.getStarttlsType() + "\"");
            }
            return new StarttlsPlainLoginResult(vulnerable);
        } catch (Exception E) {
            LOGGER.error("Could not scan for " + getProbeName(), E);
            return new StarttlsPlainLoginResult(TestResult.ERROR_DURING_TEST);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE
                && scannerConfig.getStarttlsDelegate().getStarttlsType() != StarttlsType.FTP;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new StarttlsPlainLoginResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {

    }

    private TestResult executeIMAP(Config tlsConfig) throws IOException {
        // LOGIN
        WorkflowTrace traceLogin = createEntryTrace(tlsConfig);
        traceLogin.addTlsAction(new SendAsciiAction("log LOGIN " + tlsConfig.getPlainUser() + " "
                + tlsConfig.getPlainPwd() + "\r\n", "US-ASCII"));
        ReceiveAsciiAction responseActionLogin = new ReceiveAsciiAction("", "US-ASCII");
        traceLogin.addTlsAction(responseActionLogin);
        State stateLogin = new State(tlsConfig, traceLogin);

        // AUTHENTICATE PLAIN
        WorkflowTrace tracePlain = createEntryTrace(tlsConfig);
        tracePlain.addTlsAction(new SendAsciiAction("pla AUTHENTICATE PLAIN " + new String(createSASL(tlsConfig))
                + "\r\n", "US-ASCII"));
        ReceiveAsciiAction responseActionPlain = new ReceiveAsciiAction("", "US-ASCII");
        tracePlain.addTlsAction(responseActionPlain);
        State statePlain = new State(tlsConfig, tracePlain);

        executeState(stateLogin, statePlain);
        String responseLogin = responseActionLogin.getReceivedAsciiString();
        String responsePlain = responseActionPlain.getReceivedAsciiString();

        if ((responseLogin.contains("OK") && responseLogin.contains("log"))
                || (responsePlain.contains("OK") && responsePlain.contains("pla")))
            return TestResult.TRUE;

        return TestResult.FALSE;
    }

    private TestResult executePOP3(Config tlsConfig) throws IOException {
        // LOGIN
        ReceiveAsciiAction responseActionUser = new ReceiveAsciiAction("", "US-ASCII");
        ReceiveAsciiAction responseActionPass = new ReceiveAsciiAction("", "US-ASCII");

        WorkflowTrace traceLogin = createEntryTrace(tlsConfig);
        traceLogin.addTlsAction(new SendAsciiAction("USER " + tlsConfig.getPlainUser() + "\r\n", "US-ASCII"));
        traceLogin.addTlsAction(responseActionUser);
        traceLogin.addTlsAction(new SendAsciiAction("PASS " + tlsConfig.getPlainPwd() + "\r\n", "US-ASCII"));
        traceLogin.addTlsAction(responseActionPass);
        State stateLogin = new State(tlsConfig, traceLogin);

        // AUTHENTICATE PLAIN
        WorkflowTrace tracePlain = createEntryTrace(tlsConfig);
        tracePlain.addTlsAction(new SendAsciiAction("AUTH PLAIN " + new String(createSASL(tlsConfig)) + "\r\n",
                "US-ASCII"));
        ReceiveAsciiAction responseActionPlain = new ReceiveAsciiAction("", "US-ASCII");
        tracePlain.addTlsAction(responseActionPlain);
        State statePlain = new State(tlsConfig, tracePlain);

        executeState(stateLogin, statePlain);
        String responseLoginUser = responseActionUser.getReceivedAsciiString();
        String responseLoginPass = responseActionPass.getReceivedAsciiString();
        String responsePlain = responseActionPlain.getReceivedAsciiString();

        if ((responseLoginUser.contains("+OK") && responseLoginPass.contains("+OK")) || responsePlain.contains("+OK"))
            return TestResult.TRUE;

        return TestResult.FALSE;
    }

    private TestResult executeSMTP(Config tlsConfig) throws IOException {
        // LOGIN
        ReceiveAsciiAction responseActionLogin = new ReceiveAsciiAction("", "US-ASCII");
        ReceiveAsciiAction responseActionUser = new ReceiveAsciiAction("", "US-ASCII");
        ReceiveAsciiAction responseActionPass = new ReceiveAsciiAction("", "US-ASCII");

        WorkflowTrace traceLogin = createEntryTrace(tlsConfig);
        traceLogin.addTlsAction(new SendAsciiAction("AUTH LOGIN\r\n", "US-ASCII"));
        traceLogin.addTlsAction(responseActionLogin);
        traceLogin.addTlsAction(new SendAsciiAction(new String(createSASL(tlsConfig.getPlainUser())), "US-ASCII"));
        traceLogin.addTlsAction(responseActionUser);
        traceLogin.addTlsAction(new SendAsciiAction(new String(createSASL(tlsConfig.getPlainPwd())), "US-ASCII"));
        traceLogin.addTlsAction(responseActionPass);
        State stateLogin = new State(tlsConfig, traceLogin);

        // AUTHENTICATE PLAIN
        WorkflowTrace tracePlain = createEntryTrace(tlsConfig);
        tracePlain.addTlsAction(new SendAsciiAction("AUTH PLAIN " + new String(createSASL(tlsConfig)) + "\r\n",
                "US-ASCII"));
        ReceiveAsciiAction responseActionPlain = new ReceiveAsciiAction("", "US-ASCII");
        tracePlain.addTlsAction(responseActionPlain);
        State statePlain = new State(tlsConfig, tracePlain);

        executeState(stateLogin, statePlain);

        String responseLogin = responseActionLogin.getReceivedAsciiString();
        String responseUser = responseActionUser.getReceivedAsciiString();
        String responsePass = responseActionPass.getReceivedAsciiString();
        String responsePlain = responseActionPlain.getReceivedAsciiString();

        if ((responseLogin.contains("334") && responseUser.contains("334") && responsePass.contains("235"))
                || responsePlain.contains("235"))
            return TestResult.TRUE;

        return TestResult.FALSE;
    }

    private WorkflowTrace createEntryTrace(Config tlsConfig) {
        WorkflowTrace workflowTrace = new WorkflowTrace();
        AliasedConnection connection = tlsConfig.getDefaultClientConnection();
        workflowTrace.addTlsAction(StarttlsActionFactory.createServerGreetingAction(tlsConfig, connection,
                ConnectionEndType.SERVER, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createStarttlsCommunicationAction(tlsConfig, connection,
                ConnectionEndType.CLIENT, StarttlsMessageFactory.CommandType.C_CAPA, "US-ASCII"));
        workflowTrace.addTlsAction(StarttlsActionFactory.createServerCapabilitiesAction(tlsConfig, connection,
                ConnectionEndType.SERVER, "US-ASCII"));

        return workflowTrace;
    }

    private byte[] createSASL(Config tlsConfig) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(new byte[1]);
        outputStream.write(tlsConfig.getPlainUser().getBytes());
        outputStream.write(new byte[1]);
        outputStream.write(tlsConfig.getPlainPwd().getBytes());

        return Base64.encode(outputStream.toByteArray());
    }

    private byte[] createSASL(String str) throws IOException {
        return Base64.encode(str.getBytes());
    }
}
