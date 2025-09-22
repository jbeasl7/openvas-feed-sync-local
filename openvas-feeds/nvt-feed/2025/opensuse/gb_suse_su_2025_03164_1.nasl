# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03164.1");
  script_cve_id("CVE-2025-55004", "CVE-2025-55005", "CVE-2025-55154", "CVE-2025-55160", "CVE-2025-55212", "CVE-2025-55298", "CVE-2025-57803");
  script_tag(name:"creation_date", value:"2025-09-15 04:06:57 +0000 (Mon, 15 Sep 2025)");
  script_version("2025-09-15T05:39:20+0000");
  script_tag(name:"last_modification", value:"2025-09-15 05:39:20 +0000 (Mon, 15 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:25:21 +0000 (Fri, 15 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03164-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03164-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503164-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248784");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041649.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2025:03164-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2025-55004: Fixed heap buffer over-read in in ReadOneMNGIMage when processing images with separate alpha channels
 (bsc#1248076).
- CVE-2025-55005: Fixed heap buffer overflow when transforming from Log to sRGB colorspaces (bsc#1248077).
- CVE-2025-55154: Fixed integer overflow when performing magnified size calculations in ReadOneMNGIMage (bsc#1248078).
- CVE-2025-55160: Fixed undefined behavior due to function-type-mismatch in CloneSplayTree (bsc#1248079).
- CVE-2025-55212: Fixed division-by-zero in ThumbnailImage() when passing a geometry string containing only a colon to
 `montage -geometry` (bsc#1248767).
- CVE-2025-55298: Fixed heap overflow due to format string bug vulnerability (bsc#1248780).
- CVE-2025-57803: Fixed heap out-of-bounds (OOB) write due to 32-bit integer overflow (bsc#1248784).

Other fixes:

- Fixed output file placeholders (bsc#1247475).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-limited", rpm:"ImageMagick-config-7-upstream-limited~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-open", rpm:"ImageMagick-config-7-upstream-open~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-secure", rpm:"ImageMagick-config-7-upstream-secure~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-websafe", rpm:"ImageMagick-config-7-upstream-websafe~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5-32bit", rpm:"libMagick++-7_Q16HDRI5-32bit~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5", rpm:"libMagick++-7_Q16HDRI5~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10-32bit", rpm:"libMagickCore-7_Q16HDRI10-32bit~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10", rpm:"libMagickCore-7_Q16HDRI10~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10-32bit", rpm:"libMagickWand-7_Q16HDRI10-32bit~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10", rpm:"libMagickWand-7_Q16HDRI10~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.1.1.21~150600.3.20.1", rls:"openSUSELeap15.6"))) {
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
