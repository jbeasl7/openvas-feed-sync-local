# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1114");
  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2691", "CVE-2011-2692", "CVE-2011-3045", "CVE-2011-3048", "CVE-2012-3425", "CVE-2015-7981", "CVE-2015-8126", "CVE-2015-8472", "CVE-2015-8540", "CVE-2016-10087", "CVE-2017-12652");
  script_tag(name:"creation_date", value:"2025-02-05 04:31:15 +0000 (Wed, 05 Feb 2025)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 13:51:54 +0000 (Wed, 17 Jul 2019)");

  script_name("Huawei EulerOS: Security Advisory for syslinux (EulerOS-SA-2025-1114)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1114");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1114");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'syslinux' package(s) announced via the EulerOS-SA-2025-1114 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The png_set_text_2 function in libpng 0.71 before 1.0.67, 1.2.x before 1.2.57, 1.4.x before 1.4.20, 1.5.x before 1.5.28, and 1.6.x before 1.6.27 allows context-dependent attackers to cause a NULL pointer dereference vectors involving loading a text chunk into a png structure, removing the text, and then adding another text chunk to the structure.(CVE-2016-10087)

The png_push_read_zTXt function in pngpread.c in libpng 1.0.x before 1.0.58, 1.2.x before 1.2.48, 1.4.x before 1.4.10, and 1.5.x before 1.5.10 allows remote attackers to cause a denial of service (out-of-bounds read) via a large avail_in field value in a PNG image.(CVE-2012-3425)

The png_format_buffer function in pngerror.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4 allows remote attackers to cause a denial of service (application crash) via a crafted PNG image that triggers an out-of-bounds read during the copying of error-message data. NOTE: this vulnerability exists because of a CVE-2004-0421 regression.NOTE: this is called an off-by-one error by some sources.(CVE-2011-2501)

The png_handle_sCAL function in pngrutil.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4 does not properly handle invalid sCAL chunks, which allows remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impact via a crafted PNG image that triggers the reading of uninitialized memory.(CVE-2011-2692)

The png_convert_to_rfc1123 function in png.c in libpng 1.0.x before 1.0.64, 1.2.x before 1.2.54, and 1.4.x before 1.4.17 allows remote attackers to obtain sensitive process memory information via crafted tIME chunk data in an image file, which triggers an out-of-bounds read.(CVE-2015-7981)

The png_err function in pngerror.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4 makes a function call using a NULL pointer argument instead of an empty-string argument, which allows remote attackers to cause a denial of service (application crash) via a crafted PNG image.(CVE-2011-2691)

Buffer overflow in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before 1.5.4, when used by an application that calls the png_rgb_to_gray function but not the png_set_expand function, allows remote attackers to overwrite memory with an arbitrary amount of data, and possibly have unspecified other impact, via a crafted PNG image.(CVE-2011-2690)

The png_set_text_2 function in pngset.c in libpng 1.0.x before 1.0.59, 1.2.x before 1.2.49, 1.4.x before 1.4.11, and 1.5.x before 1.5.10 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted text chunk in a PNG image file, which triggers a memory allocation failure that is not properly handled, leading to a heap-based buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'syslinux' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"syslinux", rpm:"syslinux~6.04~5.h5.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslinux-nonlinux", rpm:"syslinux-nonlinux~6.04~5.h5.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
