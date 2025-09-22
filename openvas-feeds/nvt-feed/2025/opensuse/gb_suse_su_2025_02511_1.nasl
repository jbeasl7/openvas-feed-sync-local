# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02511.1");
  script_cve_id("CVE-2025-53014", "CVE-2025-53015", "CVE-2025-53019", "CVE-2025-53101");
  script_tag(name:"creation_date", value:"2025-07-28 04:22:08 +0000 (Mon, 28 Jul 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 17:52:28 +0000 (Tue, 26 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02511-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02511-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502511-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246534");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-July/021950.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2025:02511-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

- CVE-2025-53014: Fixed an off-by-one error may cause an out-of-bounds memory access (bsc#1246530)
- CVE-2025-53015: Fixed specific XMP file conversion may cause an infinite loop (bsc#1246531)
- CVE-2025-53019: Fixed format specifiers in a filename template may cause a memory leak (bsc#1246534)
- CVE-2025-53101: Fixed input manipulation may lead to an out-of-bound write (bsc#1246529)

Changed policies:

 * allow ImageMagick to read it's own files again (bsc#1246065)");

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

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-limited", rpm:"ImageMagick-config-7-upstream-limited~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-open", rpm:"ImageMagick-config-7-upstream-open~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-secure", rpm:"ImageMagick-config-7-upstream-secure~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream-websafe", rpm:"ImageMagick-config-7-upstream-websafe~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5-32bit", rpm:"libMagick++-7_Q16HDRI5-32bit~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI5", rpm:"libMagick++-7_Q16HDRI5~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10-32bit", rpm:"libMagickCore-7_Q16HDRI10-32bit~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI10", rpm:"libMagickCore-7_Q16HDRI10~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10-32bit", rpm:"libMagickWand-7_Q16HDRI10-32bit~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI10", rpm:"libMagickWand-7_Q16HDRI10~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.1.1.21~150600.3.13.1", rls:"openSUSELeap15.6"))) {
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
