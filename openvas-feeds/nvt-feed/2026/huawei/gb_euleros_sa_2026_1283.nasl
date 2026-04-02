# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1283");
  script_cve_id("CVE-2025-66293", "CVE-2026-22695", "CVE-2026-22801");
  script_tag(name:"creation_date", value:"2026-03-10 04:52:39 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 18:58:18 +0000 (Wed, 21 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for libpng (EulerOS-SA-2026-1283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1283");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libpng' package(s) announced via the EulerOS-SA-2026-1283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From 1.6.26 to 1.6.53, there is an integer truncation in the libpng simplified write API functions png_write_image_16bit and png_write_image_8bit causes heap buffer over-read when the caller provides a negative row stride (for bottom-up image layouts) or a stride exceeding 65535 bytes. The bug was introduced in libpng 1.6.26 (October 2016) by casts added to silence compiler warnings on 16-bit systems. This vulnerability is fixed in 1.6.54.(CVE-2026-22801)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From 1.6.51 to 1.6.53, there is a heap buffer over-read in the libpng simplified API function png_image_finish_read when processing interlaced 16-bit PNGs with 8-bit output format and non-minimal row stride. This is a regression introduced by the fix for CVE-2025-65018. This vulnerability is fixed in 1.6.54.(CVE-2026-22695)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. Prior to 1.6.52, an out-of-bounds read vulnerability in libpng's simplified API allows reading up to 1012 bytes beyond the png_sRGB_base[512] array when processing valid palette PNG images with partial transparency and gamma correction. The PNG files that trigger this vulnerability are valid per the PNG specification, the bug is in libpng's internal state management. Upgrade to libpng 1.6.52 or later.(CVE-2025-66293)");

  script_tag(name:"affected", value:"'libpng' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.38~2.h3.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
