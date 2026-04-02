# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1559");
  script_cve_id("CVE-2025-64505", "CVE-2025-64506", "CVE-2025-64720", "CVE-2025-65018", "CVE-2025-66293");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for libpng (EulerOS-SA-2026-1559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1559");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1559");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libpng' package(s) announced via the EulerOS-SA-2026-1559 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, a heap buffer over-read vulnerability exists in libpng's png_write_image_8bit function when processing 8-bit images through the simplified write API with convert_to_8bit enabled. The vulnerability affects 8-bit grayscale+alpha, RGB/RGBA, and images with incomplete row data. A conditional guard incorrectly allows 8-bit input to enter code expecting 16-bit input, causing reads up to 2 bytes beyond allocated buffer boundaries. This issue has been patched in version 1.6.51.(CVE-2025-64506)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. Prior to version 1.6.51, a heap buffer over-read vulnerability exists in libpng's png_do_quantize function when processing PNG files with malformed palette indices. The vulnerability occurs when palette_lookup array bounds are not validated against externally-supplied image data, allowing an attacker to craft a PNG file with out-of-range palette indices that trigger out-of-bounds memory access. This issue has been patched in version 1.6.51.(CVE-2025-64505)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, there is a heap buffer overflow vulnerability in the libpng simplified API function png_image_finish_read when processing 16-bit interlaced PNGs with 8-bit output format. Attacker-crafted interlaced PNG files cause heap writes beyond allocated buffer bounds. This issue has been patched in version 1.6.51.(CVE-2025-65018)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. From version 1.6.0 to before 1.6.51, an out-of-bounds read vulnerability exists in png_image_read_composite when processing palette images with PNG_FLAG_OPTIMIZE_ALPHA enabled. The palette compositing code in png_init_read_transformations incorrectly applies background compositing during premultiplication, violating the invariant component <= alpha x 257 required by the simplified PNG API. This issue has been patched in version 1.6.51.(CVE-2025-64720)

LIBPNG is a reference library for use in applications that read, create, and manipulate PNG (Portable Network Graphics) raster image files. Prior to 1.6.52, an out-of-bounds read vulnerability in libpng's simplified API allows reading up to 1012 bytes beyond the png_sRGB_base[512] array when processing valid palette PNG images with partial transparency and gamma correction. The PNG files that trigger this vulnerability are valid per the PNG specification, the bug is in libpng's internal state management. Upgrade to libpng 1.6.52 or later.(CVE-2025-66293)");

  script_tag(name:"affected", value:"'libpng' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.37~1.h3.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
