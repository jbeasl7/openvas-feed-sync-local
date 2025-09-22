# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3531.1");
  script_cve_id("CVE-2011-5325", "CVE-2018-1000500", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2021-28831");
  script_tag(name:"creation_date", value:"2021-10-28 06:33:39 +0000 (Thu, 28 Oct 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 17:21:26 +0000 (Thu, 30 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3531-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3531-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213531-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951562");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009658.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2021:3531-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

- CVE-2021-28831: Fixed invalid free or segmentation fault via malformed gzip data (bsc#1184522).
- CVE-2018-20679: Fixed out of bounds read in udhcp (bsc#1121426).
- CVE-2018-1000517: Fixed buffer overflow in the retrieve_file_data() (bsc#1099260).
- CVE-2011-5325: Fixed a directory traversal related to 'tar' command (bsc#951562).
- CVE-2018-1000500: Fixed missing SSL certificate validation related to the 'wget' command (bsc#1099263).");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.26.2~4.5.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.26.2~4.5.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.26.2~4.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.26.2~4.5.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.26.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.26.2~4.5.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.26.2~4.5.1", rls:"SLES15.0SP1"))) {
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
