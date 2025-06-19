/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/**
 * AfterProbe implementation that checks for vulnerability to the Logjam attack by detecting support
 * for weak DH_EXPORT cipher suites.
 *
 * @param <ReportT> the type of TLS scan report this probe operates on
 */
public class LogjamAfterProbe<ReportT extends TlsScanReport> extends AfterProbe<ReportT> {

    /**
     * Analyzes the supported cipher suites to determine if the server is vulnerable to the Logjam
     * attack. A server is vulnerable if it supports any DH_EXPORT cipher suites (including
     * DH_anon_EXPORT, DH_DSS_EXPORT, DH_RSA_EXPORT, DHE_DSS_EXPORT, or DHE_RSA_EXPORT). Sets the
     * result to TRUE if vulnerable, FALSE if not vulnerable, UNCERTAIN if cipher suites cannot be
     * determined, or ERROR_DURING_TEST if an exception occurs.
     *
     * @param report the TLS scan report containing supported cipher suite information
     */
    @Override
    public void analyze(ReportT report) {
        TestResult vulnerable = TestResults.NOT_TESTED_YET;
        try {
            if (report.getSupportedCipherSuites() != null) {
                for (CipherSuite suite : report.getSupportedCipherSuites()) {
                    if (suite.name().contains("DH_anon_EXPORT")
                            || suite.name().contains("DH_DSS_EXPORT")
                            || suite.name().contains("DH_RSA_EXPORT")
                            || suite.name().contains("DHE_DSS_EXPORT")
                            || suite.name().contains("DHE_RSA_EXPORT")) {
                        vulnerable = TestResults.TRUE;
                    }
                }
                if (vulnerable != TestResults.TRUE) {
                    vulnerable = TestResults.FALSE;
                }
            } else {
                vulnerable = TestResults.UNCERTAIN;
            }
        } catch (Exception e) {
            vulnerable = TestResults.ERROR_DURING_TEST;
        }
        report.putResult(TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM, vulnerable);
    }
}
