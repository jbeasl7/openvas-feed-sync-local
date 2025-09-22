# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2298.1");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5156", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5168", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5188", "CVE-2018-6126");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 18:44:37 +0000 (Thu, 06 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2298-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2298-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182298-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2018:2298-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to the 52.9 ESR release fixes the following issues:
These security issues were fixed:
- Firefox ESR 52.9:
- CVE-2018-5188 Memory safety bugs fixed in Firefox 60, Firefox ESR 60.1,
 and Firefox ESR 52.9 (bsc#1098998).
- CVE-2018-12368 No warning when opening executable SettingContent-ms
 files (bsc#1098998).
- CVE-2018-12366 Invalid data handling during QCMS transformations
 (bsc#1098998).
- CVE-2018-12365 Compromised IPC child process can list local filenames
 (bsc#1098998).
- CVE-2018-12364 CSRF attacks through 307 redirects and NPAPI plugins
 (bsc#1098998).
- CVE-2018-12363 Use-after-free when appending DOM nodes (bsc#1098998).
- CVE-2018-12362 Integer overflow in SSSE3 scaler (bsc#1098998).
- CVE-2018-12360 Use-after-free when using focus() (bsc#1098998).
- CVE-2018-5156 Media recorder segmentation fault when track type is
 changed during capture (bsc#1098998).
- CVE-2018-12359 Buffer overflow using computed size of canvas element
 (bsc#1098998).
- Firefox ESR 52.8:
- CVE-2018-6126: Prevent heap buffer overflow in rasterizing paths in SVG
 with Skia (bsc#1096449).
- CVE-2018-5183: Backport critical security fixes in Skia (bsc#1092548).
- CVE-2018-5154: Use-after-free with SVG animations and clip paths
 (bsc#1092548).
- CVE-2018-5155: Use-after-free with SVG animations and text paths
 (bsc#1092548).
- CVE-2018-5157: Same-origin bypass of PDF Viewer to view protected PDF
 files (bsc#1092548).
- CVE-2018-5158: Malicious PDF can inject JavaScript into PDF Viewer
 (bsc#1092548).
- CVE-2018-5159: Integer overflow and out-of-bounds write in Skia
 (bsc#1092548).
- CVE-2018-5168: Lightweight themes can be installed without user
 interaction (bsc#1092548).
- CVE-2018-5178: Buffer overflow during UTF-8 to Unicode string conversion
 through legacy extension (bsc#1092548).
- CVE-2018-5150: Memory safety bugs fixed in Firefox 60 and Firefox ESR
 52.8 (bsc#1092548).
These non-security issues were fixed:
- Various stability and regression fixes
- Performance improvements to the Safe Browsing service to avoid slowdowns
 while updating site classification data");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~52.9.0esr~3.7.12", rls:"SLES15.0"))) {
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
