# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1771.1");
  script_cve_id("CVE-2020-14093", "CVE-2020-14154", "CVE-2020-14954");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-26 19:58:57 +0000 (Fri, 26 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1771-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1771-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201771-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173197");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/007042.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt' package(s) announced via the SUSE-SU-2020:1771-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mutt fixes the following issues:

- CVE-2020-14954: Fixed a response injection due to a STARTTLS buffering issue which was
 affecting IMAP, SMTP, and POP3 (bsc#1173197).
- CVE-2020-14093: Fixed a potential IMAP Man-in-the-Middle attack via a PREAUTH response (bsc#1172906, bsc#1172935).
- CVE-2020-14154: Fixed an issue where Mutt was ignoring an expired certificate and was
 proceeding with a connection (bsc#1172906, bsc#1172935).");

  script_tag(name:"affected", value:"'mutt' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-debuginfo", rpm:"mutt-debuginfo~1.10.1~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-debugsource", rpm:"mutt-debugsource~1.10.1~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.10.1~3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-lang", rpm:"mutt-lang~1.10.1~3.8.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-debuginfo", rpm:"mutt-debuginfo~1.10.1~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-debugsource", rpm:"mutt-debugsource~1.10.1~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.10.1~3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-lang", rpm:"mutt-lang~1.10.1~3.8.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.10.1~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-lang", rpm:"mutt-lang~1.10.1~3.8.1", rls:"SLES15.0"))) {
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
