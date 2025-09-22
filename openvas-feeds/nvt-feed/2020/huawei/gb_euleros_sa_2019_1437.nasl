# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1437");
  script_cve_id("CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244", "CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-8870", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-6223", "CVE-2016-9532", "CVE-2018-19210", "CVE-2019-6128", "CVE-2019-7663");
  script_tag(name:"creation_date", value:"2020-01-23 11:46:40 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-24 21:12:56 +0000 (Tue, 24 Jan 2017)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2019-1437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1437");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1437");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2019-1437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap-based buffer overflow in the readgifimage function in the gif2tiff tool in libtiff 4.0.3 and earlier allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a crafted height and width values in a GIF image.(CVE-2013-4243)

Integer overflow in tools/bmp2tiff.c in LibTIFF before 4.0.4 allows remote attackers to cause a denial of service (heap-based buffer over-read), or possibly obtain sensitive information from process memory, via crafted width and length values in RLE4 or RLE8 data in a BMP file.(CVE-2015-8870)

LibTIFF 4.0.3 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted TIFF image to the (1) checkInkNamesString function in tif_dir.c in the thumbnail tool, (2) compresscontig function in tiff2bw.c in the tiff2bw tool, (3) putcontig8bitCIELab function in tif_getimage.c in the tiff2rgba tool, LZWPreDecode function in tif_lzw.c in the (4) tiff2ps or (5) tiffdither tool, (6) NeXTDecode function in tif_next.c in the tiffmedian tool, or (7) TIFFWriteDirectoryTagLongLong8Array function in tif_dirwrite.c in the tiffset tool.(CVE-2014-8127)

Use-after-free vulnerability in the t2p_readwrite_pdf_image function in tools/tiff2pdf.c in libtiff 4.0.3 allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted TIFF image.(CVE-2013-4232)

Integer overflow in the writeBufferToSeparateStrips function in tiffcrop.c in LibTIFF before 4.0.7 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted tif file.(CVE-2016-9532)

Multiple integer overflows in the (1) cvt_by_strip and (2) cvt_by_tile functions in the tiff2rgba tool in LibTIFF 4.0.6 and earlier, when -b mode is enabled, allow remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted TIFF image, which triggers an out-of-bounds write.(CVE-2016-3945)

The (1) putcontig8bitYCbCr21tile function in tif_getimage.c or (2) NeXTDecode function in tif_next.c in LibTIFF allows remote attackers to cause a denial of service (uninitialized memory access) via a crafted TIFF image, as demonstrated by libtiff-cvs-1.tif and libtiff-cvs-2.tif.(CVE-2014-9655)

A flaw was discovered in the bmp2tiff utility. By tricking a user into processing a specially crafted file, a remote attacker could exploit this flaw to cause a crash or memory corruption and, possibly, execute arbitrary code with the privileges of the user running the libtiff tool.(CVE-2014-9330)

The TIFFReadRawStrip1 and TIFFReadRawTile1 functions in tif_read.c in libtiff before 4.0.7 allows remote attackers to cause a denial of service (crash) or possibly obtain sensitive information via a negative index in a file-content buffer.(CVE-2016-6223)

The _TIFFmalloc function in tif_unix.c in LibTIFF 4.0.3 does not reject a zero size, which allows remote attackers to cause a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~27.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
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
