# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3879.1");
  script_cve_id("CVE-2015-8870", "CVE-2016-3619", "CVE-2016-3620", "CVE-2016-3621", "CVE-2016-5319", "CVE-2016-9273", "CVE-2017-17942", "CVE-2017-9117", "CVE-2017-9147", "CVE-2018-12900", "CVE-2018-18661");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:34 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-24 18:30:08 +0000 (Wed, 24 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3879-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183879-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983440");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-November/004880.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:3879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

Security issues fixed:

- CVE-2018-18661: Fixed NULL pointer dereference in the function LZWDecode in the file tif_lzw.c (bsc#1113672).
- CVE-2018-12900: Fixed heap-based buffer overflow in the cpSeparateBufToContigBuf (bsc#1099257).
- CVE-2017-9147: Fixed invalid read in the _TIFFVGetField function in tif_dir.c, that allowed remote attackers to cause a DoS via acrafted TIFF file (bsc#1040322).
- CVE-2017-9117: Fixed BMP images processing that was verified without biWidth and biHeight values (bsc#1040080).
- CVE-2017-17942: Fixed issue in the function PackBitsEncode that could have led to a heap overflow and caused a DoS (bsc#1074186).
- CVE-2016-9273: Fixed heap-based buffer overflow issue (bsc#1010163).
- CVE-2016-5319: Fixed heap-based buffer overflow in PackBitsEncode (bsc#983440).
- CVE-2016-3621: Fixed out-of-bounds read in the bmp2tiff tool (lzw packing) (bsc#974448).
- CVE-2016-3620: Fixed out-of-bounds read in the bmp2tiff tool (zip packing) (bsc#974447)
- CVE-2016-3619: Fixed out-of-bounds read in the bmp2tiff tool (none packing) (bsc#974446)
- CVE-2015-8870: Fixed integer overflow in tools/bmp2tiff.c that allowed remote attackers to causea DOS (bsc#1014461).

Non-security issues fixed:

- asan_build: build ASAN included
- debug_build: build more suitable for debugging");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~141.169.22.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-32bit", rpm:"libtiff3-32bit~3.8.2~141.169.22.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-x86", rpm:"libtiff3-x86~3.8.2~141.169.22.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~3.8.2~141.169.22.1", rls:"SLES11.0SP4"))) {
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
