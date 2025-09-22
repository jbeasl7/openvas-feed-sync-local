# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1457.1");
  script_cve_id("CVE-2014-3566", "CVE-2015-8076", "CVE-2015-8077", "CVE-2015-8078");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-04 14:34:26 +0000 (Fri, 04 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1457-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1457-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161457-1.html");
  script_xref(name:"URL", value:"https://bugzilla.cyrusimap.org/show_bug.cgi?id=3867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981670");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd' package(s) announced via the SUSE-SU-2016:1457-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Previous versions of cyrus-imapd would not allow its users to disable old
 protocols like SSLv1 and SSLv2 that are unsafe due to various known attacks
 like BEAST and POODLE. [link moved to references]
 remedies this issue by adding the configuration option 'tls_versions' to the
 imapd.conf file. Note that users who upgrade existing installation of this
 package will *not* have their imapd.conf file overwritten, i.e. their IMAP
 server will continue to support SSLv1 and SSLv2 like before. To disable
 support for those protocols, it's necessary to edit imapd.conf manually to
 state 'tls_versions: tls1_0 tls1_1 tls1_2'. New installations, however, will
 have an imapd.conf file that contains these settings already, i.e. newly
 installed IMAP servers do *not* support SSLv1 and SSLv2 unless that support
 is explicitly enabled by the user. (bsc#901748)

- An integer overflow vulnerability in cyrus-imapd's urlfetch range checking
 code was fixed. (CVE-2015-8076, CVE-2015-8077, CVE-2015-8078, bsc#981670,
 bsc#954200, bsc#954201)

- Support for Elliptic Curve Diffie-Hellman (ECDH) has been added to
 cyrus-imapd. (bsc#860611)");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-IMAP", rpm:"perl-Cyrus-IMAP~2.3.18~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve", rpm:"perl-Cyrus-SIEVE-managesieve~2.3.18~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-IMAP", rpm:"perl-Cyrus-IMAP~2.3.18~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve", rpm:"perl-Cyrus-SIEVE-managesieve~2.3.18~37.1", rls:"SLES12.0SP1"))) {
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
