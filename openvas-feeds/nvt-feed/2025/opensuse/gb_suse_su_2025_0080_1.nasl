# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856918");
  script_cve_id("CVE-2025-0237", "CVE-2025-0238", "CVE-2025-0239", "CVE-2025-0240", "CVE-2025-0241", "CVE-2025-0242", "CVE-2025-0243");
  script_tag(name:"creation_date", value:"2025-01-14 05:00:06 +0000 (Tue, 14 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0080-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250080-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234991");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020098.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:0080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-0237 (bmo#1915257)
 WebChannel APIs susceptible to confused deputy attack
 - CVE-2025-0238 (bmo#1915535)
 Use-after-free when breaking lines in text
 - CVE-2025-0239 (bmo#1929156)
 Alt-Svc ALPN validation failure when redirected
 - CVE-2025-0240 (bmo#1929623)
 Compartment mismatch when parsing JavaScript JSON module
 - CVE-2025-0241 (bmo#1933023)
 Memory corruption when using JavaScript Text Segmentation
 - CVE-2025-0242 (bmo#1874523, bmo#1926454, bmo#1931873,
 bmo#1932169)
 Memory safety bugs fixed in Firefox 134, Thunderbird 134,
 Firefox ESR 115.19, Firefox ESR 128.6, Thunderbird 115.19,
 and Thunderbird 128.6
 - CVE-2025-0243 (bmo#1827142, bmo#1932783)
 Memory safety bugs fixed in Firefox 134, Thunderbird 134,
 Firefox ESR 128.6, and Thunderbird 128.6

Other fixes:

 - fixed: New mail notification was not hidden after reading the
 new message (bmo#1920077)
 - fixed: New mail notification could show for the wrong folder,
 causing repeated alerts (bmo#1926462)
 - fixed: macOS shortcut CMD+1 did not restore the main window
 when it was minimized (bmo#1857953)
 - fixed: Clicking the context menu 'Reply' button resulted in
 'Reply-All' (bmo#1935883)
 - fixed: Switching from 'All', 'Unread', and 'Threads with
 unread' did not work (bmo#1921618)
 - fixed: Downloading message headers from a newsgroup could
 cause a hang (bmo#1931661)
 - fixed: Message list performance slow when many updates
 happened at once (bmo#1933104)
 - fixed: 'mailto:' links did not apply the compose format of
 the current identity (bmo#550414)
 - fixed: Authentication failure of AUTH PLAIN or AUTH LOGIN did
 not fall back to USERPASS (bmo#1928026)");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.6.0~150200.8.197.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.6.0~150200.8.197.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.6.0~150200.8.197.1", rls:"openSUSELeap15.6"))) {
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
