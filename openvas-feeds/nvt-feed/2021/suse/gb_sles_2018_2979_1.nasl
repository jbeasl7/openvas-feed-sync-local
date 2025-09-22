# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2979.1");
  script_cve_id("CVE-2018-16741", "CVE-2018-16742", "CVE-2018-16743", "CVE-2018-16744", "CVE-2018-16745");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 17:08:56 +0000 (Thu, 01 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2979-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2979-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182979-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108762");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mgetty' package(s) announced via the SUSE-SU-2018:2979-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mgetty fixes the following security issues:

- CVE-2018-16741: The function do_activate() did not properly sanitize shell
 metacharacters to prevent command injection (bsc#1108752)
- CVE-2018-16745: The mail_to parameter was not sanitized, leading to a buffer
 overflow if long untrusted input reached it (bsc#1108756)
- CVE-2018-16744: The mail_to parameter was not sanitized, leading to command
 injection if untrusted input reached reach it (bsc#1108757)
- CVE-2018-16742: Prevent stack-based buffer overflow that could have been
 triggered via a command-line parameter (bsc#1108762)
- CVE-2018-16743: The command-line parameter username wsa passed unsanitized to
 strcpy(), which could have caused a stack-based buffer overflow (bsc#1108761)");

  script_tag(name:"affected", value:"'mgetty' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"g3utils", rpm:"g3utils~1.1.36~58.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mgetty", rpm:"mgetty~1.1.36~58.3.1", rls:"SLES12.0SP3"))) {
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
