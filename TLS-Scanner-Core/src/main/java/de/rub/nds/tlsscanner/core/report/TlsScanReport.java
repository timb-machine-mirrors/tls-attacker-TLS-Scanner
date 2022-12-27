/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class TlsScanReport extends ScanReport {

	private ProtocolType protocolType = null;

	private KnownPaddingOracleVulnerability knownPaddingOracleVulnerability = null;

	// Extensions
	private List<String> supportedAlpns = null;

	// DTLS
	private Integer totalReceivedRetransmissions = 0;

	// Scan Timestamps
	private long scanStartTime;
	private long scanEndTime;

	public TlsScanReport() {
		super();
	}

	public synchronized ProtocolType getProtocolType() {
		return protocolType;
	}

	public synchronized void setProtocolType(ProtocolType protocolType) {
		this.protocolType = protocolType;
	}

	public synchronized KnownPaddingOracleVulnerability getKnownPaddingOracleVulnerability() {
		return knownPaddingOracleVulnerability;
	}

	public synchronized void setKnownPaddingOracleVulnerability(
			KnownPaddingOracleVulnerability knownPaddingOracleVulnerability) {
		this.knownPaddingOracleVulnerability = knownPaddingOracleVulnerability;
	}

	public synchronized List<String> getSupportedAlpns() {
		return supportedAlpns;
	}

	public synchronized void setSupportedAlpns(List<String> supportedAlpns) {
		this.supportedAlpns = supportedAlpns;
	}

	public synchronized Integer getTotalReceivedRetransmissions() {
		return totalReceivedRetransmissions;
	}

	public synchronized void setTotalReceivedRetransmissions(Integer totalReceivedRetransmissions) {
		this.totalReceivedRetransmissions = totalReceivedRetransmissions;
	}

	public synchronized long getScanStartTime() {
		return scanStartTime;
	}

	public synchronized void setScanStartTime(long scanStartTime) {
		this.scanStartTime = scanStartTime;
	}

	public synchronized long getScanEndTime() {
		return scanEndTime;
	}

	public synchronized void setScanEndTime(long scanEndTime) {
		this.scanEndTime = scanEndTime;
	}

	public synchronized Boolean getCcaSupported() {
		return this.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE;
	}

	public synchronized Boolean getCcaRequired() {
		return this.getResult(TlsAnalyzedProperty.REQUIRES_CCA) == TestResults.TRUE;
	}

	@SuppressWarnings("unchecked")
	public synchronized Map<HandshakeMessageType, Integer> getRetransmissionCounters() {
		MapResult<?, ?> mapResult = getMapResult(TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS);
		return mapResult == null ? new HashMap<>() : (Map<HandshakeMessageType, Integer>) mapResult.getMap();
	}

	List<NamedGroup> list;

	@SuppressWarnings("unchecked")
	public synchronized Set<CipherSuite> getSupportedCipherSuites() {
		SetResult<?> setResult = getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES);
		return setResult == null ? new HashSet<>() : (Set<CipherSuite>) setResult.getSet();
	}

	public synchronized List<EntropyReport> getEntropyReports() {
		@SuppressWarnings("unchecked")
		ListResult<EntropyReport> listResult = (ListResult<EntropyReport>) getListResult(
				TlsAnalyzedProperty.ENTROPY_REPORTS);
		return listResult == null ? new LinkedList<>() : listResult.getList();
	}

	public synchronized List<InformationLeakTest<PaddingOracleTestInfo>> getPaddingOracleTestResultList() {
		@SuppressWarnings("unchecked")
		ListResult<InformationLeakTest<PaddingOracleTestInfo>> listResult = (ListResult<InformationLeakTest<PaddingOracleTestInfo>>) getListResult(
				TlsAnalyzedProperty.PADDINGORACLE_TEST_RESULT);
		return listResult == null ? new LinkedList<>() : listResult.getList();
	}

	public synchronized List<CertificateChain> getCertificateChainList() {
		@SuppressWarnings("unchecked")
		ListResult<CertificateChain> listResult = (ListResult<CertificateChain>) getListResult(
				TlsAnalyzedProperty.CERTIFICATE_CHAINS);
		return listResult == null ? new LinkedList<>() : listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<CipherSuite> getClientAdvertisedCiphersuites() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES);
		return listResult == null ? new LinkedList<>() : (List<CipherSuite>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS);
		return listResult == null ? new LinkedList<>() : (List<VersionSuiteListPair>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS);
		return listResult == null ? new LinkedList<>() : (List<ProtocolVersion>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsCert() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT);
		return listResult == null ? new LinkedList<>() : (List<SignatureAndHashAlgorithm>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE);
		return listResult == null ? new LinkedList<>() : (List<SignatureAndHashAlgorithm>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsTls13() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13);
		return listResult == null ? new LinkedList<>() : (List<SignatureAndHashAlgorithm>) listResult.getList();
	}

	public synchronized List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
		Set<SignatureAndHashAlgorithm> combined = new HashSet<>();
		if (getSupportedSignatureAndHashAlgorithmsCert() != null) {
			combined.addAll(getSupportedSignatureAndHashAlgorithmsCert());
		}
		if (getSupportedSignatureAndHashAlgorithmsSke() != null) {
			combined.addAll(getSupportedSignatureAndHashAlgorithmsSke());
		}
		return new LinkedList<>(combined);
	}

	@SuppressWarnings("unchecked")
	public synchronized List<ExtensionType> getSupportedExtensions() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS);
		return listResult == null ? new LinkedList<>() : (List<ExtensionType>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);
		return listResult == null ? new LinkedList<>() : (List<CompressionMethod>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getSupportedTls13Groups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getSupportedNamedGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getEphemeralEcdsaPkgGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getTls13EcdsaPkgGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getStaticEcdsaSigGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getEphemeralEcdsaSigGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<NamedGroup> getTls13EcdsaSigGroups() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS);
		return listResult == null ? new LinkedList<>() : (List<NamedGroup>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<HttpsHeader> getHttpsHeader() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.HTTPS_HEADER);
		return listResult == null ? new LinkedList<>() : (List<HttpsHeader>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<TokenBindingVersion> getSupportedTokenbindingVersions() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_VERSIONS);
		return listResult == null ? new LinkedList<>() : (List<TokenBindingVersion>) listResult.getList();
	}

	@SuppressWarnings("unchecked")
	public synchronized List<TokenBindingKeyParameters> getSupportedTokenbindingKeyParameters() {
		ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_KEY_PARAMETERS);
		return listResult == null ? new LinkedList<>() : (List<TokenBindingKeyParameters>) listResult.getList();
	}

}
