# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1447");
  script_cve_id("CVE-2016-10092", "CVE-2016-10266", "CVE-2016-10267", "CVE-2016-10268", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-10272", "CVE-2016-10371", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-5102", "CVE-2016-5318", "CVE-2016-5321", "CVE-2016-5323", "CVE-2016-9273", "CVE-2016-9538", "CVE-2016-9539", "CVE-2017-10688", "CVE-2017-12944", "CVE-2017-13726", "CVE-2017-13727", "CVE-2017-17095", "CVE-2017-7592", "CVE-2017-7593", "CVE-2017-7594", "CVE-2017-7595", "CVE-2017-7596", "CVE-2017-7597", "CVE-2017-7598", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601", "CVE-2017-7602", "CVE-2017-9117", "CVE-2017-9147", "CVE-2017-9403", "CVE-2017-9936", "CVE-2018-10779", "CVE-2018-10963", "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-18557", "CVE-2018-18661", "CVE-2018-7456", "CVE-2018-8905", "CVE-2019-14973", "CVE-2019-17546");
  script_tag(name:"creation_date", value:"2020-04-16 05:54:04 +0000 (Thu, 16 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-24 18:30:08 +0000 (Wed, 24 May 2017)");

  script_name("Huawei EulerOS: Security Advisory for libtiff (EulerOS-SA-2020-1447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1447");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1447");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtiff' package(s) announced via the EulerOS-SA-2020-1447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tools/pal2rgb.c in pal2rgb in LibTIFF 4.0.9 allows remote attackers to cause a denial of service (TIFFSetupStrips heap-based buffer overflow and application crash) or possibly have unspecified other impact via a crafted TIFF file.(CVE-2017-17095)

The _TIFFFax3fillruns function in libtiff before 4.0.6 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted Tiff image.The _TIFFFax3fillruns function in libtiff before 4.0.6 allows remote attackers to cause a denial of service (divide-by-zero error and application crash) via a crafted Tiff image.(CVE-2016-5323)

The cvtClump function in the rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (out-of-bounds write) by setting the '-v' option to -1.(CVE-2016-3624)

The rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote attackers to cause a denial of service (divide-by-zero) by setting the (1) v or (2) h parameter to 0.(CVE-2016-3623)

LibTIFF 4.0.9 (with JBIG enabled) decodes arbitrarily-sized JBIG into a buffer, ignoring the buffer size, which leads to a tif_jbig.c JBIGDecode out-of-bounds write.(CVE-2018-18557)

An issue was discovered in LibTIFF 4.0.9. There are two out-of-bounds writes in cpTags in tools/tiff2bw.c and tools/pal2rgb.c, which can cause a denial of service (application crash) or possibly have unspecified other impact via a crafted image file.(CVE-2018-17101)

An issue was discovered in LibTIFF 4.0.9. There is a int32 overflow in multiply_ms in tools/ppm2tiff.c, which can cause a denial of service (crash) or possibly have unspecified other impact via a crafted image file.(CVE-2018-17100)

In LibTIFF 4.0.9, a heap-based buffer overflow occurs in the function LZWDecodeCompat in tif_lzw.c via a crafted TIFF file, as demonstrated by tiff2ps.(CVE-2018-8905)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via a crafted TIFF image, related to 'WRITE of size 2048' and libtiff/tif_next.c:64:9.(CVE-2016-10272)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service (heap-based buffer over-read) or possibly have unspecified other impact via a crafted TIFF image, related to 'READ of size 8' and libtiff/tif_read.c:523:22.(CVE-2016-10270)

LibTIFF 4.0.7 allows remote attackers to cause a denial of service (heap-based buffer over-read) or possibly have unspecified other impact via a crafted TIFF image, related to 'READ of size 512' and libtiff/tif_unix.c:340:2.(CVE-2016-10269)

tools/tiffcp.c in LibTIFF 4.0.7 allows remote attackers to cause a denial of service (integer underflow and heap-based buffer under-read) or possibly have unspecified other impact via a crafted TIFF image, related to 'READ of size 78490' and libtiff/tif_unix.c:115:23.(CVE-2016-10268)

Heap-based buffer overflow in the readContigStripsIntoBuffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'libtiff' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~27.h22.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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
