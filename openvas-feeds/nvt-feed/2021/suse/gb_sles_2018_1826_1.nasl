# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1826.1");
  script_cve_id("CVE-2016-3632", "CVE-2016-8331", "CVE-2017-11613", "CVE-2017-13726", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-8905");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 12:36:10 +0000 (Thu, 12 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1826-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1826-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181826-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974621");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-June/004224.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:1826-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

These security issues were fixed:

- CVE-2017-18013: There was a Null-Pointer Dereference in the tif_print.c TIFFPrintDirectory function, as demonstrated by a tiffinfo crash. (bsc#1074317)
- CVE-2018-10963: The TIFFWriteDirectorySec() function in tif_dirwrite.c allowed remote attackers to cause a denial of service (assertion failure and application crash) via a crafted file, a different vulnerability than CVE-2017-13726. (bsc#1092949)
- CVE-2018-7456: Prevent a NULL Pointer dereference in the function TIFFPrintDirectory when using the tiffinfo tool to print crafted TIFF information, a different vulnerability than CVE-2017-18013 (bsc#1082825)
- CVE-2017-11613: Prevent denial of service in the TIFFOpen function. During the TIFFOpen process, td_imagelength is not checked. The value of td_imagelength can be directly controlled by an input file. In the ChopUpSingleUncompressedStrip function, the _TIFFCheckMalloc function is called based on td_imagelength. If the value of td_imagelength is set close to the amount of system memory, it will hang the system or trigger the OOM killer (bsc#1082332)
- CVE-2018-8905: Prevent heap-based buffer overflow in the function LZWDecodeCompat via a crafted TIFF file (bsc#1086408)
- CVE-2016-8331: Prevent remote code execution because of incorrect handling of TIFF images. A crafted TIFF document could have lead to a type confusion vulnerability resulting in remote code execution. This vulnerability could have been be triggered via a TIFF file delivered to the application using LibTIFF's tag extension functionality (bsc#1007276)
- CVE-2016-3632: The _TIFFVGetField function allowed remote attackers to cause a denial of service (out-of-bounds write) or execute arbitrary code via a crafted TIFF image (bsc#974621)");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~44.15.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~44.15.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.9~44.15.2", rls:"SLES12.0SP3"))) {
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
