# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1166.1");
  script_cve_id("CVE-2015-5186");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-13 11:17:22 +0000 (Wed, 13 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1166-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1166-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191166-1.html");
  script_xref(name:"URL", value:"http://people.redhat.com/sgrubb/audit/ChangeLog");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941922");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-May/005428.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audit' package(s) announced via the SUSE-SU-2019:1166-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for audit fixes the following issues:

Audit on SUSE Linux Enterprise 12 SP3 was updated to 2.8.1 to bring new features and bugfixes. (bsc#1125535 FATE#326346)

* Many features were added to auparse_normalize
* cli option added to auditd and audispd for setting config dir
* In auditd, restore the umask after creating a log file
* Option added to auditd for skipping email verification

The full changelog can be found here: [link moved to references]


- Change openldap dependency to client only (bsc#1085003)

Minor security issue fixed:

- CVE-2015-5186: Audit: log terminal emulator escape sequences handling (bsc#941922)");

  script_tag(name:"affected", value:"'audit' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"audit", rpm:"audit~2.8.1~8.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"audit-audispd-plugins", rpm:"audit-audispd-plugins~2.8.1~8.3.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudit1", rpm:"libaudit1~2.8.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaudit1-32bit", rpm:"libaudit1-32bit~2.8.1~8.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libauparse0", rpm:"libauparse0~2.8.1~8.3.1", rls:"SLES12.0SP3"))) {
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
