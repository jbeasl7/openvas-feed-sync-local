# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0736.1");
  script_cve_id("CVE-2024-47220", "CVE-2024-49761");
  script_tag(name:"creation_date", value:"2025-03-03 04:08:07 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:41:46 +0000 (Tue, 05 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0736-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250736-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232440");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020450.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.5' package(s) announced via the SUSE-SU-2025:0736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.5 fixes the following issues:

- CVE-2024-47220: Fixed a HTTP request smuggling attack in WEBrick (bsc#1230930)
- CVE-2024-49761: Fixed a ReDoS vulnerability in ruby rexml (bsc#1232440)

Other fixes:

- [ruby/uri] Fix quadratic backtracking on invalid relative URI
- [ruby/time] Make RFC2822 regexp linear
- [ruby/time] Fix quadratic backtracking on invalid time
- merge some parts of CGI 0.1.1");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.9~150000.4.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.9~150000.4.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.9~150000.4.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.9~150000.4.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.9~150000.4.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.9~150000.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.9~150000.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.9~150000.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.9~150000.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.9~150000.4.36.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.9~150000.4.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.9~150000.4.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.9~150000.4.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.9~150000.4.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.9~150000.4.36.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.9~150000.4.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.9~150000.4.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.9~150000.4.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.9~150000.4.36.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.9~150000.4.36.1", rls:"SLES15.0SP6"))) {
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
