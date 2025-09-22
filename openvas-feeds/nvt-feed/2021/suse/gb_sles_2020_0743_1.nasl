# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0743.1");
  script_cve_id("CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388", "CVE-2018-6459");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-27 17:22:33 +0000 (Tue, 27 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0743-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200743-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2020:0743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for strongswan fixes the following issues:

Strongswan was updated to version 5.8.2 (jsc#SLE-11370).

Security issue fixed:

CVE-2018-6459: Fixed a DoS vulnerability in the parser for PKCS#1
 RSASSA-PSS signatures that was caused by insufficient input validation
 (bsc#1079548).

Full changelogs:

Version 5.8.2

 * Identity-based CA constraints, which enforce that the certificate
 chain of the remote peer contains a CA certificate with a specific
 identity, are supported via vici/swanctl.conf. This is similar to the
 existing CA constraints but doesn't require that the CA certificate is
 locally installed, for instance, intermediate CA certificates received
 from the peers. Wildcard identity matching (e.g. ..., OU=Research,
 CN=*) could also be used for the latter but requires trust in the
 intermediate CAs to only issue certificates with legitimate subject
 DNs (e.g. the 'Sales' CA must not issue certificates with
 OU=Research). With the new constraint that's not necessary as long as
 a path length basic constraint (--pathlen for pki --issue) prevents
 intermediate CAs from issuing further intermediate CAs.
 * Intermediate CA certificates may now be sent in hash-and-URL encoding
 by configuring a base URL for the parent CA (#3234,
 swanctl/rw-hash-and-url-multi-level).
 * Implemented NIST SP-800-90A Deterministic Random Bit Generator (DRBG)
 based on AES-CTR and SHA2-HMAC modes. Currently used by the gmp and
 ntru plugins.
 * Random nonces sent in an OCSP requests are now expected in the
 corresponding OCSP responses.
 * The kernel-netlink plugin now ignores deprecated IPv6 addresses for
 MOBIKE. Whether temporary
 or permanent IPv6 addresses are included now depends on the
 charon.prefer_temporary_addrs setting (#3192).
 * Extended Sequence Numbers (ESN) are configured via PF_KEY if supported
 by the kernel.
 * The PF_KEY socket's receive buffer in the kernel-pfkey plugin is now
 cleared before sending requests, as many of the messages sent by the
 kernel are sent as broadcasts to all PF_KEY sockets. This is an issue
 if an external tool is used to manage SAs/policies unrelated to IPsec
 (#3225).
 * The vici plugin now uses unique section names for CHILD_SAs in
 child-updown events (7c74ce9190).
 * For individually deleted CHILD_SAs (in particular for IKEv1) the vici
 child-updown event now includes more information about the CHILD_SAs
 such as traffic statistics (#3198).
 * Custom loggers are correctly re-registered if log levels are changed
 via stroke loglevel (#3182).
 * Avoid lockups during startup on low entropy systems when using OpenSSL
 1.1.1 (095a2c2eac).
 * Instead of failing later when setting a key, creating HMACs via
 openssl plugin now fails instantly if the underlying hash algorithm
 isn't supported (e.g. MD5 in FIPS-mode) so fallbacks to other plugins
 work properly (#3284).
 * Exponents of RSA keys read from TPM 2.0 via SAPI are correctly
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'strongswan' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.8.2~4.6.14", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
