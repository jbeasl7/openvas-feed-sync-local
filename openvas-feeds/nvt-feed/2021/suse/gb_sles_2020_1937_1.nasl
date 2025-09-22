# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1937.1");
  script_cve_id("CVE-2017-9814");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 14:26:37 +0000 (Wed, 19 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1937-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201937-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cairo' package(s) announced via the SUSE-SU-2020:1937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cairo fixes the following issues:

Fix a memory corruption in pango.

Revert 'Correctly decode Adobe CMYK JPEGs in PDF export'.

Add more FreeeType font color conversions to support COLR/CPAL.

Fix crash when rendering Microsoft's Segoe UI Emoji Regular font.

Fix memory leaks found by Coverity.

Fix assertion failure in the freetype backend. (fdo#105746).

Add cairo-CVE-2017-9814.patch: Replace malloc with _cairo_malloc and
 check cmap size before allocating (bsc#1049092)");

  script_tag(name:"affected", value:"'cairo' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-debuginfo", rpm:"libcairo-script-interpreter2-debuginfo~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit-debuginfo", rpm:"libcairo2-32bit-debuginfo~1.16.0~4.8.1", rls:"SLES15.0SP1"))) {
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
