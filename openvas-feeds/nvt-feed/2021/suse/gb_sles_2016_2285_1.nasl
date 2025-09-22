# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2285.1");
  script_cve_id("CVE-2013-4566", "CVE-2014-3566", "CVE-2015-5244", "CVE-2016-3099");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 16:16:24 +0000 (Wed, 16 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2285-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2285-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162285-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979688");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002267.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_nss' package(s) announced via the SUSE-SU-2016:2285-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides apache2-mod_nss 1.0.14, which brings several fixes and enhancements:

- Fix OpenSSL ciphers stopped parsing at +. (CVE-2016-3099)
- Created valgrind suppression files to ease debugging.
- Implement SSL_PPTYPE_FILTER to call executables to get the key password pins.
- Improvements to migrate.pl.
- Update default ciphers to something more modern and secure.
- Check for host and netstat commands in gencert before trying to use them.
- Add server support for DHE ciphers.
- Extract SAN from server/client certificates into env
- Fix memory leaks and other coding issues caught by clang analyzer.
- Add support for Server Name Indication (SNI).
- Add support for SNI for reverse proxy connections.
- Add RenegBufferSize? option.
- Add support for TLS Session Tickets (RFC 5077).
- Fix logical AND support in OpenSSL cipher compatibility.
- Correctly handle disabled ciphers. (CVE-2015-5244)
- Implement a slew more OpenSSL cipher macros.
- Fix a number of illegal memory accesses and memory leaks.
- Support for SHA384 ciphers if they are available in NSS.
- Add compatibility for mod_ssl-style cipher definitions.
- Add TLSv1.2-specific ciphers.
- Completely remove support for SSLv2.
- Add support for sqlite NSS databases.
- Compare subject CN and VS hostname during server start up.
- Add support for enabling TLS v1.2.
- Don't enable SSL 3 by default. (CVE-2014-3566)
- Fix CVE-2013-4566.
- Move nss_pcache to /usr/libexec.
- Support httpd 2.4+.
- Use apache2-systemd-ask-pass to prompt for a certificate passphrase.
 (bsc#972968, bsc#975394)");

  script_tag(name:"affected", value:"'apache2-mod_nss' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_nss", rpm:"apache2-mod_nss~1.0.14~18.3", rls:"SLES12.0SP1"))) {
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
