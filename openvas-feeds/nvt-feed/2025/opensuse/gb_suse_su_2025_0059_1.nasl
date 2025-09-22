# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856913");
  script_cve_id("CVE-2025-0237", "CVE-2025-0238", "CVE-2025-0239", "CVE-2025-0240", "CVE-2025-0241", "CVE-2025-0242", "CVE-2025-0243");
  script_tag(name:"creation_date", value:"2025-01-11 05:00:46 +0000 (Sat, 11 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0059-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250059-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234991");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:0059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Firefox Extended Support Release 128.6.0 ESR
 * Fixed: Various security fixes.

 MFSA 2025-02 (bsc#1234991)
 * CVE-2025-0237 (bmo#1915257)
 WebChannel APIs susceptible to confused deputy attack
 * CVE-2025-0238 (bmo#1915535)
 Use-after-free when breaking lines
 * CVE-2025-0239 (bmo#1929156)
 Alt-Svc ALPN validation failure when redirected
 * CVE-2025-0240 (bmo#1929623)
 Compartment mismatch when parsing JavaScript JSON module
 * CVE-2025-0241 (bmo#1933023)
 Memory corruption when using JavaScript Text Segmentation
 * CVE-2025-0242 (bmo#1874523, bmo#1926454, bmo#1931873,
 bmo#1932169)
 Memory safety bugs fixed in Firefox 134, Thunderbird 134,
 Firefox ESR 115.19, Firefox ESR 128.6, Thunderbird 115.19,
 and Thunderbird 128.6
 * CVE-2025-0243 (bmo#1827142, bmo#1932783)
 Memory safety bugs fixed in Firefox 134, Thunderbird 134,
 Firefox ESR 128.6, and Thunderbird 128.6

- Firefox Extended Support Release 128.5.2 ESR
 * Fixed: Fixed a crash experienced by Windows users with Qihoo
 360 Total Security Antivirus software installed (bmo#1934258)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.6.0~150200.152.167.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~128.6.0~150200.152.167.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.6.0~150200.152.167.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.6.0~150200.152.167.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.6.0~150200.152.167.1", rls:"openSUSELeap15.6"))) {
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
