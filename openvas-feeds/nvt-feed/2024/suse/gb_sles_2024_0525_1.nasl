# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0525.1");
  script_cve_id("CVE-2019-14889", "CVE-2020-16135", "CVE-2020-1730", "CVE-2021-3634", "CVE-2023-1667", "CVE-2023-2283", "CVE-2023-48795", "CVE-2023-6004", "CVE-2023-6918");
  script_tag(name:"creation_date", value:"2024-02-19 10:04:44 +0000 (Mon, 19 Feb 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-23 17:25:06 +0000 (Mon, 23 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0525-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240525-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218209");
  script_xref(name:"URL", value:"https://git.libssh.org/projects/libssh.git/tag/?h=libssh-0.9.6");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017947.html");
  script_xref(name:"URL", value:"https://www.libssh.org/2020/04/09/libssh-0-9-4-and-libssh-0-8-9-security-release/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the SUSE-SU-2024:0525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh fixes the following issues:

Update to version 0.9.8 (jsc#PED-7719):

* Fix CVE-2023-6004: Command injection using proxycommand (bsc#1218209)
* Fix CVE-2023-48795: Potential downgrade attack using strict kex (bsc#1218126)
* Fix CVE-2023-6918: Missing checks for return values of MD functions (bsc#1218186)
* Allow @ in usernames when parsing from URI composes

Update to version 0.9.7:

* Fix CVE-2023-1667: a NULL dereference during rekeying with algorithm
 guessing (bsc#1211188)
* Fix CVE-2023-2283: a possible authorization bypass in
 pki_verify_data_signature under low-memory conditions (bsc#1211190)
* Fix several memory leaks in GSSAPI handling code

Update to version 0.9.6 (bsc#1189608, CVE-2021-3634):

* [link moved to references]


Update to 0.9.5 (bsc#1174713, CVE-2020-16135):

* CVE-2020-16135: Avoid null pointer dereference in sftpserver (T232)
* Improve handling of library initialization (T222)
* Fix parsing of subsecond times in SFTP (T219)
* Make the documentation reproducible
* Remove deprecated API usage in OpenSSL
* Fix regression of ssh_channel_poll_timeout() returning SSH_AGAIN
* Define version in one place (T226)
* Prevent invalid free when using different C runtimes than OpenSSL (T229)
* Compatibility improvements to testsuite

Update to version 0.9.4

* [link moved to references]
* Fix possible Denial of Service attack when using AES-CTR-ciphers
 CVE-2020-1730 (bsc#1168699)

Update to version 0.9.3

* Fixed CVE-2019-14889 - SCP: Unsanitized location leads to command execution (bsc#1158095)
* SSH-01-003 Client: Missing NULL check leads to crash in erroneous state
* SSH-01-006 General: Various unchecked Null-derefs cause DOS
* SSH-01-007 PKI Gcrypt: Potential UAF/double free with RSA pubkeys
* SSH-01-010 SSH: Deprecated hash function in fingerprinting
* SSH-01-013 Conf-Parsing: Recursive wildcards in hostnames lead to DOS
* SSH-01-014 Conf-Parsing: Integer underflow leads to OOB array access
* SSH-01-001 State Machine: Initial machine states should be set explicitly
* SSH-01-002 Kex: Differently bound macros used to iterate same array
* SSH-01-005 Code-Quality: Integer sign confusion during assignments
* SSH-01-008 SCP: Protocol Injection via unescaped File Names
* SSH-01-009 SSH: Update documentation which RFCs are implemented
* SSH-01-012 PKI: Information leak via uninitialized stack buffer

Update to version 0.9.2

* Fixed libssh-config.cmake
* Fixed issues with rsa algorithm negotiation (T191)
* Fixed detection of OpenSSL ed25519 support (T197)

Update to version 0.9.1

* Added support for Ed25519 via OpenSSL
* Added support for X25519 via OpenSSL
* Added support for localuser in Match keyword
* Fixed Match keyword to be case sensitive
* Fixed compilation with LibreSSL
* Fixed error report of channel open (T75)
* Fixed sftp documentation (T137)
* Fixed known_hosts parsing (T156)
* Fixed build issue with MinGW (T157)
* Fixed build ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libssh' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.9.8~150200.13.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.8~150200.13.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.8~150200.13.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4-32bit", rpm:"libssh4-32bit~0.9.8~150200.13.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.9.8~150200.13.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.8~150200.13.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.8~150200.13.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4-32bit", rpm:"libssh4-32bit~0.9.8~150200.13.3.1", rls:"SLES15.0SP3"))) {
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
