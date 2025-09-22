# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14173.1");
  script_cve_id("CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-9812");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:19 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-13 19:51:58 +0000 (Mon, 13 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14173-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14173-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914173-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149303");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, firefox-glib2, firefox-gtk3' package(s) announced via the SUSE-SU-2019:14173-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, firefox-glib2, firefox-gtk3 fixes the following issues:

Mozilla Firefox was updated to the 60.9.0esr release:

Security Advisory MFSA 2019-27:

* Use-after-free while manipulating video
 CVE-2019-11746 (bmo#1564449, bsc#1149297)
* XSS by breaking out of title and textarea elements using innerHTML
 CVE-2019-11744 (bmo#1562033, bsc#1149297)
* Same-origin policy violation with SVG filters and canvas to steal
 cross-origin images
 CVE-2019-11742 (bmo#1559715, bsc#1149303)
* Privilege escalation with Mozilla Maintenance Service in custom
 Firefox installation location
 CVE-2019-11753 (bmo#1574980, bsc#1149295)
* Use-after-free while extracting a key value in IndexedDB
 CVE-2019-11752 (bmo#1501152, bsc#1149296)
* Sandbox escape through Firefox Sync
 CVE-2019-9812 (bmo#1538008, bmo#1538015, bsc#1149294)
* Cross-origin access to unload event attributes
 CVE-2019-11743 (bmo#1560495, bsc#1149298)
 Navigation-Timing Level 2 specification
* Memory safety bugs fixed in Firefox 69, Firefox ESR 68.1, and Firefox ESR 60.9
 CVE-2019-11740 (bmo#1563133, bmo#1573160, bsc#1149299)

- Rebuild glib2 schemas on SLE-11 (bsc#1145550)

Changes in firefox-glib2:

- Fix the rpm macros %glib2_gsettings_schema_* which were replaced with
 %nil in Factory because they're no longer needed, but we still need
 them in SLE11 (bsc#1145550)

Changes in firefox-gtk3:

- Rebuild so %glib2_gsettings_schema_post gets called with fixed
 rpm macros %glib2_gsettings_schema_* in firefox-glib2 package
 which were replaced with %nil in Factory because they're no
 longer needed, but we still need them in SLE11 (bsc#1145550)");

  script_tag(name:"affected", value:"'MozillaFirefox, firefox-glib2, firefox-gtk3' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.9.0esr~78.46.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.9.0esr~78.46.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.9.0esr~78.46.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gio-branding-upstream", rpm:"firefox-gio-branding-upstream~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-lang", rpm:"firefox-glib2-lang~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-tools", rpm:"firefox-glib2-tools~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-branding-upstream", rpm:"firefox-gtk3-branding-upstream~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-data", rpm:"firefox-gtk3-data~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-amharic", rpm:"firefox-gtk3-immodule-amharic~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-inuktitut", rpm:"firefox-gtk3-immodule-inuktitut~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-multipress", rpm:"firefox-gtk3-immodule-multipress~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-thai", rpm:"firefox-gtk3-immodule-thai~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-vietnamese", rpm:"firefox-gtk3-immodule-vietnamese~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-xim", rpm:"firefox-gtk3-immodule-xim~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodules-tigrigna", rpm:"firefox-gtk3-immodules-tigrigna~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-lang", rpm:"firefox-gtk3-lang~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-tools", rpm:"firefox-gtk3-tools~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgtk-3-0", rpm:"firefox-libgtk-3-0~3.10.9~2.12.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gio-2_0-0", rpm:"libfirefox-gio-2_0-0~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-glib-2_0-0", rpm:"libfirefox-glib-2_0-0~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gmodule-2_0-0", rpm:"libfirefox-gmodule-2_0-0~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gobject-2_0-0", rpm:"libfirefox-gobject-2_0-0~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gthread-2_0-0", rpm:"libfirefox-gthread-2_0-0~2.54.3~2.11.1", rls:"SLES11.0SP4"))) {
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
