# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1368.1");
  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-5836", "CVE-2017-6440", "CVE-2017-7982");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-23 16:00:21 +0000 (Mon, 23 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1368-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171368-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035312");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002907.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libplist' package(s) announced via the SUSE-SU-2017:1368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libplist fixes the following security issues:

- CVE-2017-5545: The main function in plistutil.c in libimobiledevice libplist allowed attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via Apple Property List data that is too short. (bsc#1021610).
- CVE-2017-5209: The base64decode function in base64.c in libimobiledevice libplist through 1.12 allows attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via split encoded Apple Property List data. (bsc#1019531)
- CVE-2017-5836: A type inconsistency in bplist.c was fixed. (bsc#1023807)
- CVE-2017-5835: A memory allocation error leading to DoS was fixed. (bsc#1023822)
- CVE-2017-5834: A heap-buffer overflow in parse_dict_node was fixed (bsc#1023848)
- CVE-2017-7982: Denial of service (heap-based buffer over-read and application crash) via a crafted plist file (bsc#1035312)
- CVE-2017-6440: A specially crafted plist file could lead to denial of service (bsc#1029631)");

  script_tag(name:"affected", value:"'libplist' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libplist1", rpm:"libplist1~1.8~10.9.1", rls:"SLES12.0SP1"))) {
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
