# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2569.1");
  script_cve_id("CVE-2016-10371", "CVE-2017-7592", "CVE-2017-7593", "CVE-2017-7594", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7598", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602", "CVE-2017-9403", "CVE-2017-9404");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-13 14:15:32 +0000 (Thu, 13 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2569-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2569-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172569-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042805");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003259.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2017:2569-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff to version 4.0.8 fixes a several bugs and security issues:

These security issues were fixed:

- CVE-2017-7595: The JPEGSetupEncode function allowed remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted image (bsc#1033127).
- CVE-2016-10371: The TIFFWriteDirectoryTagCheckedRational function allowed remote attackers to cause a denial of service (assertion failure and application exit) via a crafted TIFF file (bsc#1038438).
- CVE-2017-7598: Error in tif_dirread.c allowed remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted image (bsc#1033118).
- CVE-2017-7596: Undefined behavior because of floats outside their expected value range, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033126).
- CVE-2017-7597: Undefined behavior because of floats outside their expected value range, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033120).
- CVE-2017-7599: Undefined behavior because of shorts outside their expected value range, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033113).
- CVE-2017-7600: Undefined behavior because of chars outside their expected value range, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033112).
- CVE-2017-7601: Because of a shift exponent too large for 64-bit type long undefined behavior was caused, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033111).
- CVE-2017-7602: Prevent signed integer overflow, which allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033109).
- CVE-2017-7592: The putagreytile function had a left-shift undefined behavior issue, which might allowed remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image (bsc#1033131).
- CVE-2017-7593: Ensure that tif_rawdata is properly initialized, to prevent remote attackers to obtain sensitive information from process memory via a crafted image (bsc#1033129).
- CVE-2017-7594: The OJPEGReadHeaderInfoSecTablesDcTable function allowed remote attackers to cause a denial of service (memory leak) via a crafted image (bsc#1033128).
- CVE-2017-9403: Prevent memory leak in function TIFFReadDirEntryLong8Array, which allowed attackers to cause a denial of service via a crafted file (bsc#1042805).
- CVE-2017-9404: Fixed memory ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.8~44.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.8~44.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.8~44.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.8~44.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.8~44.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.8~44.3.1", rls:"SLES12.0SP3"))) {
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
