# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20121.1");
  script_cve_id("CVE-2025-68431");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620121-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255735");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-January/043750.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif' package(s) announced via the SUSE-SU-2026:20121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libheif fixes the following issues:

- CVE-2025-68431: heap buffer over-read in `HeifPixelImage::overlay()` via crafted HEIF file that exercises the overlay
 image item path (bsc#1255735).");

  script_tag(name:"affected", value:"'libheif' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-libheif", rpm:"gdk-pixbuf-loader-libheif~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-aom", rpm:"libheif-aom~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-dav1d", rpm:"libheif-dav1d~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-ffmpeg", rpm:"libheif-ffmpeg~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-jpeg", rpm:"libheif-jpeg~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-openjpeg", rpm:"libheif-openjpeg~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-rav1e", rpm:"libheif-rav1e~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-svtenc", rpm:"libheif-svtenc~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.19.7~160000.3.1", rls:"SLES16.0.0"))) {
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
