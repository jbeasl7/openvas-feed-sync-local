# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1835.1");
  script_cve_id("CVE-2014-8128", "CVE-2015-7554", "CVE-2016-10095", "CVE-2016-10266", "CVE-2016-3632", "CVE-2016-5318", "CVE-2016-8331", "CVE-2016-9535", "CVE-2016-9540", "CVE-2017-11613", "CVE-2017-18013", "CVE-2017-5225", "CVE-2018-7456", "CVE-2018-8905");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-12 17:06:22 +0000 (Thu, 12 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1835-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181835-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974621");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004228.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:1835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following security issues:

- CVE-2017-5225: Prevent heap buffer overflow in the tools/tiffcp that could
 have caused DoS or code execution via a crafted BitsPerSample value
 (bsc#1019611)
- CVE-2018-7456: Prevent a NULL Pointer dereference in the function
 TIFFPrintDirectory when using the tiffinfo tool to print crafted TIFF
 information, a different vulnerability than CVE-2017-18013 (bsc#1082825)
- CVE-2017-11613: Prevent denial of service in the TIFFOpen function. During
 the TIFFOpen process, td_imagelength is not checked. The value of
 td_imagelength can be directly controlled by an input file. In the
 ChopUpSingleUncompressedStrip function, the _TIFFCheckMalloc function is called
 based on td_imagelength. If the value of td_imagelength is set close to the
 amount of system memory, it will hang the system or trigger the OOM killer
 (bsc#1082332)
- CVE-2016-10266: Prevent remote attackers to cause a denial of service
 (divide-by-zero error and application crash) via a crafted TIFF image, related
 to libtiff/tif_read.c:351:22 (bsc#1031263)
- CVE-2018-8905: Prevent heap-based buffer overflow in the function
 LZWDecodeCompat via a crafted TIFF file (bsc#1086408)
- CVE-2016-9540: Prevent out-of-bounds write on tiled images with odd tile
 width versus image width (bsc#1011839).
- CVE-2016-9535: tif_predict.h and tif_predict.c had assertions that could have
 lead to assertion failures in debug mode, or buffer overflows in release mode,
 when dealing with unusual tile size like YCbCr with subsampling (bsc#1011846).
- CVE-2016-9535: tif_predict.h and tif_predict.c had assertions that could have
 lead to assertion failures in debug mode, or buffer overflows in release mode,
 when dealing with unusual tile size like YCbCr with subsampling (bsc#1011846).
- Removed assert in readSeparateTilesIntoBuffer() function (bsc#1017689).
- CVE-2016-10095: Prevent stack-based buffer overflow in the _TIFFVGetField
 function that allowed remote attackers to cause a denial of service (crash) via
 a crafted TIFF file (bsc#1017690).
- CVE-2016-8331: Prevent remote code execution because of incorrect handling of
 TIFF images. A crafted TIFF document could have lead to a type confusion
 vulnerability resulting in remote code execution. This vulnerability could have
 been be triggered via a TIFF file delivered to the application using LibTIFF's
 tag extension functionality (bsc#1007276).
- CVE-2016-3632: The _TIFFVGetField function allowed remote attackers to cause
 a denial of service (out-of-bounds write) or execute arbitrary code via a
 crafted TIFF image (bsc#974621).");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff3", rpm:"libtiff3~3.8.2~141.169.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-32bit", rpm:"libtiff3-32bit~3.8.2~141.169.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff3-x86", rpm:"libtiff3-x86~3.8.2~141.169.9.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~3.8.2~141.169.9.1", rls:"SLES11.0SP4"))) {
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
