# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886717");
  script_cve_id("CVE-2023-45681", "CVE-2023-47212");
  script_tag(name:"creation_date", value:"2024-05-27 10:45:29 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-01 16:15:07 +0000 (Wed, 01 May 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-4c8d4cda0d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4c8d4cda0d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4c8d4cda0d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278401");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278402");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stb' package(s) announced via the FEDORA-2024-4c8d4cda0d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-45681 / CVE-2023-47212");

  script_tag(name:"affected", value:"'stb' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"stb", rpm:"stb~0^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb-devel", rpm:"stb-devel~0^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb-doc", rpm:"stb-doc~0^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_c_lexer-devel", rpm:"stb_c_lexer-devel~0.12^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_connected_components-devel", rpm:"stb_connected_components-devel~0.96^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_divide-devel", rpm:"stb_divide-devel~0.94^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_ds-devel", rpm:"stb_ds-devel~0.67^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_dxt-devel", rpm:"stb_dxt-devel~1.12^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_easy_font-devel", rpm:"stb_easy_font-devel~1.1^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_herringbone_wang_tile-devel", rpm:"stb_herringbone_wang_tile-devel~0.7^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_hexwave-devel", rpm:"stb_hexwave-devel~0.5^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_image-devel", rpm:"stb_image-devel~2.29^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_image_resize-devel", rpm:"stb_image_resize-devel~0.97^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_image_resize2-devel", rpm:"stb_image_resize2-devel~2.06^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_image_write-devel", rpm:"stb_image_write-devel~1.16^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_leakcheck-devel", rpm:"stb_leakcheck-devel~0.6^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_perlin-devel", rpm:"stb_perlin-devel~0.5^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_rect_pack-devel", rpm:"stb_rect_pack-devel~1.1^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_sprintf-devel", rpm:"stb_sprintf-devel~1.10^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_textedit-devel", rpm:"stb_textedit-devel~1.14^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_tilemap_editor-devel", rpm:"stb_tilemap_editor-devel~0.42^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_truetype-devel", rpm:"stb_truetype-devel~1.26^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_vorbis-devel", rpm:"stb_vorbis-devel~1.22^20240213gitae721c5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stb_voxel_render-devel", rpm:"stb_voxel_render-devel~0.89^20240213gitae721c5~6.fc39", rls:"FC39"))) {
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
