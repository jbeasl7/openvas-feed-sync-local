# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01946.1");
  script_cve_id("CVE-2025-5263", "CVE-2025-5264", "CVE-2025-5265", "CVE-2025-5266", "CVE-2025-5267", "CVE-2025-5268", "CVE-2025-5269", "CVE-2025-5283");
  script_tag(name:"creation_date", value:"2025-06-16 04:13:18 +0000 (Mon, 16 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01946-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501946-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243353");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:01946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Update to Mozilla Thunderbird 128.11 (MFSA 2025-46, bsc#1243353):

- CVE-2025-5283: Double-free in libvpx encoder (bmo#1962421)
- CVE-2025-5263: Error handling for script execution was incorrectly isolated from web content (bmo#1960745)
- CVE-2025-5264: Potential local code execution in 'Copy as cURL' command (bmo#1950001)
- CVE-2025-5265: Potential local code execution in 'Copy as cURL' command (bmo#1962301)
- CVE-2025-5266: Script element events leaked cross-origin resource status (bmo#1965628)
- CVE-2025-5267: Clickjacking vulnerability could have led to leaking saved payment card details (bmo#1954137)
- CVE-2025-5268: Memory safety bugs fixed in Firefox 139, Thunderbird 139, Firefox ESR 128.11, and Thunderbird 128.11 (bmo#1950136, bmo#1958121, bmo#1960499, bmo#1962634)
- CVE-2025-5269: Memory safety bug fixed in Firefox ESR 128.11 and Thunderbird 128.11 (bmo#1924108)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.11.0~150200.8.221.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.11.0~150200.8.221.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.11.0~150200.8.221.1", rls:"openSUSELeap15.6"))) {
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
