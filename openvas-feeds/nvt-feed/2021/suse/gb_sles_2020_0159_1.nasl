# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0159.1");
  script_cve_id("CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694", "CVE-2019-15695");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-16 20:41:01 +0000 (Thu, 16 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0159-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0159-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200159-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160937");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-January/006396.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc' package(s) announced via the SUSE-SU-2020:0159-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tigervnc fixes the following issues:

- CVE-2019-15691: Fixed a use-after-return due to incorrect usage of stack memory in ZRLEDecoder (bsc#1159856).
- CVE-2019-15692: Fixed a heap-based buffer overflow in CopyRectDecode (bsc#1160250).
- CVE-2019-15693: Fixed a heap-based buffer overflow in TightDecoder::FilterGradient (bsc#1159858).
- CVE-2019-15694: Fixed a heap-based buffer overflow, caused by improper error handling in processing MemOutStream (bsc#1160251).
- CVE-2019-15695: Fixed a stack-based buffer overflow, which could be triggered from CMsgReader::readSetCursor (bsc#1159860).");

  script_tag(name:"affected", value:"'tigervnc' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libXvnc1", rpm:"libXvnc1~1.6.0~18.28.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.6.0~18.28.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~1.6.0~18.28.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libXvnc1", rpm:"libXvnc1~1.6.0~18.28.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.6.0~18.28.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~1.6.0~18.28.1", rls:"SLES12.0SP3"))) {
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
