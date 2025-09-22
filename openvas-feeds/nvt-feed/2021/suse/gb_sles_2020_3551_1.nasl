# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3551.1");
  script_cve_id("CVE-2019-17498", "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 14:10:46 +0000 (Tue, 26 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3551-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203551-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178083");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007887.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2_org' package(s) announced via the SUSE-SU-2020:3551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh2_org fixes the following issues:

- Version update to 1.9.0: [bsc#1178083, jsc#SLE-16922]
 Enhancements and bugfixes:
 * adds ECDSA keys and host key support when using OpenSSL
 * adds ED25519 key and host key support when using OpenSSL 1.1.1
 * adds OpenSSH style key file reading
 * adds AES CTR mode support when using WinCNG
 * adds PEM passphrase protected file support for Libgcrypt and WinCNG
 * adds SHA256 hostkey fingerprint
 * adds libssh2_agent_get_identity_path() and libssh2_agent_set_identity_path()
 * adds explicit zeroing of sensitive data in memory
 * adds additional bounds checks to network buffer reads
 * adds the ability to use the server default permissions when creating sftp directories
 * adds support for building with OpenSSL no engine flag
 * adds support for building with LibreSSL
 * increased sftp packet size to 256k
 * fixed oversized packet handling in sftp
 * fixed building with OpenSSL 1.1
 * fixed a possible crash if sftp stat gets an unexpected response
 * fixed incorrect parsing of the KEX preference string value
 * fixed conditional RSA and AES-CTR support
 * fixed a small memory leak during the key exchange process
 * fixed a possible memory leak of the ssh banner string
 * fixed various small memory leaks in the backends
 * fixed possible out of bounds read when parsing public keys from the server
 * fixed possible out of bounds read when parsing invalid PEM files
 * no longer null terminates the scp remote exec command
 * now handle errors when diffie hellman key pair generation fails
 * improved building instructions
 * improved unit tests

- Version update to 1.8.2: [bsc#1130103]
 Bug fixes:
 * Fixed the misapplied userauth patch that broke 1.8.1
 * moved the MAX size declarations from the public header");

  script_tag(name:"affected", value:"'libssh2_org' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit-debuginfo", rpm:"libssh2-1-32bit-debuginfo~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.9.0~4.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit-debuginfo", rpm:"libssh2-1-32bit-debuginfo~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.9.0~4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.9.0~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.9.0~4.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.9.0~4.13.1", rls:"SLES15.0"))) {
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
