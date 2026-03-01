# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0596.1");
  script_cve_id("CVE-2025-28162", "CVE-2025-28164", "CVE-2026-22695", "CVE-2026-22801", "CVE-2026-25646");
  script_tag(name:"creation_date", value:"2026-02-25 04:39:17 +0000 (Wed, 25 Feb 2026)");
  script_version("2026-02-25T05:57:40+0000");
  script_tag(name:"last_modification", value:"2026-02-25 05:57:40 +0000 (Wed, 25 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 20:43:44 +0000 (Fri, 13 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0596-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0596-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260596-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258020");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024368.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng16' package(s) announced via the SUSE-SU-2026:0596-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libpng16 fixes the following issues:

- CVE-2025-28162: memory leaks when running `pngimage` (bsc#1257364).
- CVE-2025-28164: memory leaks when running `pngimage` (bsc#1257365).
- CVE-2026-22695: heap buffer over-read in png_image_finish_read (bsc#1256525).
- CVE-2026-22801: integer truncation causing heap buffer over-read in png_image_write_* (bsc#1256526).
- CVE-2026-25646: heap buffer overflow vulnerability in png_set_dither/png_set_quantize (bsc#1258020).");

  script_tag(name:"affected", value:"'libpng16' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16", rpm:"libpng16-16~1.6.34~150000.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-32bit", rpm:"libpng16-16-32bit~1.6.34~150000.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel", rpm:"libpng16-compat-devel~1.6.34~150000.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel", rpm:"libpng16-devel~1.6.34~150000.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16", rpm:"libpng16-16~1.6.34~150000.3.19.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-16-32bit", rpm:"libpng16-16-32bit~1.6.34~150000.3.19.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-compat-devel", rpm:"libpng16-compat-devel~1.6.34~150000.3.19.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng16-devel", rpm:"libpng16-devel~1.6.34~150000.3.19.1", rls:"SLES15.0SP5"))) {
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
