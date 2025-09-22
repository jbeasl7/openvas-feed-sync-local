# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2329.1");
  script_cve_id("CVE-2013-4566", "CVE-2014-3566");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-10-15 18:51:12 +0000 (Wed, 15 Oct 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2329-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2329-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162329-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979688");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002277.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_nss' package(s) announced via the SUSE-SU-2016:2329-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides apache2-mod_nss 1.0.14, which brings several fixes and enhancements:

- SHA256 cipher names change spelling from *_sha256 to *_sha_256.
- Drop mod_nss_migrate.pl and use upstream migrate script instead.
- Check for Apache user owner/group read permissions of NSS database at startup.
- Update default ciphers to something more modern and secure.
- Check for host and netstat commands in gencert before trying to use them.
- Don't ignore NSSProtocol when NSSFIPS is enabled.
- Use proper shell syntax to avoid creating /0 in gencert.
- Add server support for DHE ciphers.
- Extract SAN from server/client certificates into env.
- Fix memory leaks and other coding issues caught by clang analyzer.
- Add support for Server Name Indication (SNI)
- Add support for SNI for reverse proxy connections.
- Add RenegBufferSize? option.
- Add support for TLS Session Tickets (RFC 5077).
- Implement a slew more OpenSSL cipher macros.
- Fix a number of illegal memory accesses and memory leaks.
- Support for SHA384 ciphers if they are available in the version of NSS mod_nss is built against.
- Add the SECURE_RENEG environment variable.
- Add some hints when NSS database cannot be initialized.
- Code cleanup including trailing whitespace and compiler warnings.
- Modernize autotools configuration slightly, add config.h.
- Add small test suite for SNI.
- Add compatibility for mod_ssl-style cipher definitions.
- Add Camelia ciphers.
- Remove Fortezza ciphers.
- Add TLSv1.2-specific ciphers.
- Initialize cipher list when re-negotiating handshake.
- Completely remove support for SSLv2.
- Add support for sqlite NSS databases.
- Compare subject CN and VS hostname during server start up.
- Add support for enabling TLS v1.2.
- Don't enable SSL 3 by default. (CVE-2014-3566)
- Improve protocol testing.
- Add nss_pcache man page.
- Fix argument handling in nss_pcache.
- Support httpd 2.4+.
- Allow users to configure a helper to ask for certificate passphrases via
 NSSPassPhraseDialog. (bsc#975394)");

  script_tag(name:"affected", value:"'apache2-mod_nss' package(s) on SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~0.4.25.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~0.4.25.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~0.4.25.1", rls:"SLES11.0SP4"))) {
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
