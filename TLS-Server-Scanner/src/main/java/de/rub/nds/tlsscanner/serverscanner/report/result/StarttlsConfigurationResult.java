/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.LinkedList;
import java.util.List;

public class StarttlsConfigurationResult extends ProbeResult {

    private TestResult vulnerable;

    private String capabilities;

    public StarttlsConfigurationResult(TestResult vulnerable) {
        this(vulnerable, "");
    }

    public StarttlsConfigurationResult(TestResult vulnerable, String capabilities) {
        super(ProbeType.STARTTLS_CONFIGURATION);
        this.vulnerable = vulnerable;
        this.capabilities = capabilities;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.OFFERS_PLAIN_LOGIN, vulnerable);
        report.setSupportedCapabilities(capabilities);
    }
}
