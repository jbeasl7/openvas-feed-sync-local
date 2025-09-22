# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0352.1");
  script_cve_id("CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-6892");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-20 14:57:05 +0000 (Tue, 20 Jun 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0352-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0352-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180352-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069874");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003705.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the SUSE-SU-2018:0352-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsndfile fixes the following issues:

- CVE-2017-16942: Divide-by-zero in the function wav_w64_read_fmt_chunk(), which may lead to Denial of service (bsc#1069874).
- CVE-2017-6892: Fixed an out-of-bounds read memory access in the aiff_read_chanmap() (bsc#1043978).
- CVE-2017-14634: In libsndfile 1.0.28, a divide-by-zero error exists in the function double64_init() in double64.c, which may lead to DoS when playing a crafted audio file. (bsc#1059911)
- CVE-2017-14245: An out of bounds read in the function d2alaw_array() in alaw.c of libsndfile 1.0.28 may lead to a remote DoS attack or information disclosure, related to mishandling of
 the NAN and INFINITY floating-point values. (bsc#1059912)
- CVE-2017-14246: An out of bounds read in the function d2ulaw_array() in ulaw.c of libsndfile 1.0.28 may lead to a remote DoS attack or information disclosure, related to mishandling of
 the NAN and INFINITY floating-point values.(bsc#1059913)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.7.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.7.2", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.25~36.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1-32bit", rpm:"libsndfile1-32bit~1.0.25~36.7.2", rls:"SLES12.0SP3"))) {
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
