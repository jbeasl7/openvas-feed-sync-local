# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2859.1");
  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-02 19:39:54 +0000 (Fri, 02 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2859-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162859-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991069");
  script_xref(name:"URL", value:"https://docs.python.org/3.4/whatsnew/changelog.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002407.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the SUSE-SU-2016:2859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides Python 3.4.5, which brings many fixes and enhancements.

The following security issues have been fixed:

- CVE-2016-1000110: CGIHandler could have allowed setting of HTTP_PROXY environment
 variable based on user supplied Proxy request header. (bsc#989523)
- CVE-2016-0772: A vulnerability in smtplib could have allowed a MITM attacker to
 perform a startTLS stripping attack. (bsc#984751)
- CVE-2016-5636: A heap overflow in Python's zipimport module. (bsc#985177)
- CVE-2016-5699: A header injection flaw in urrlib2/urllib/httplib/http.client.
 (bsc#985348)

The update also includes the following non-security fixes:

- Don't force 3rd party C extensions to be built with -Werror=declaration-after-statement.
 (bsc#951166)
- Make urllib proxy var handling behave as usual on POSIX. (bsc#983582)

For a comprehensive list of changes please refer to the upstream change log:
[link moved to references]");

  script_tag(name:"affected", value:"'python3' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_4m1_0", rpm:"libpython3_4m1_0~3.4.5~19.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.4.5~19.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-base", rpm:"python3-base~3.4.5~19.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-curses", rpm:"python3-curses~3.4.5~19.1", rls:"SLES12.0SP2"))) {
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
