# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0849.1");
  script_cve_id("CVE-2024-43097", "CVE-2025-1930", "CVE-2025-1931", "CVE-2025-1932", "CVE-2025-1933", "CVE-2025-1934", "CVE-2025-1935", "CVE-2025-1936", "CVE-2025-1937", "CVE-2025-1938", "CVE-2025-26695", "CVE-2025-26696");
  script_tag(name:"creation_date", value:"2025-03-14 04:06:16 +0000 (Fri, 14 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0849-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0849-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250849-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237683");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:0849-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

 Updated to Mozilla Thunderbird 128.8 MFSA 2025-18 (bsc#1237683):

 - CVE-2024-43097: Overflow when growing an SkRegion's RunArray
 - CVE-2025-1930: AudioIPC StreamData could trigger a use-after-free in the
 Browser process
 - CVE-2025-1931: Use-after-free in WebTransportChild
 - CVE-2025-1932: Inconsistent comparator in XSLT sorting led to out-of-bounds
 access
 - CVE-2025-1933: JIT corruption of WASM i32 return values on 64-bit CPUs
 - CVE-2025-1934: Unexpected GC during RegExp bailout processing
 - CVE-2025-1935: Clickjacking the registerProtocolHandler info-bar
 - CVE-2025-1936: Adding %00 and a fake extension to a jar: URL changed the
 interpretation of the contents
 - CVE-2025-1937: Memory safety bugs fixed in Firefox 136, Thunderbird 136,
 Firefox ESR 115.21, Firefox ESR 128.8, and Thunderbird 128.8
 - CVE-2025-1938: Memory safety bugs fixed in Firefox 136, Thunderbird 136,
 Firefox ESR 128.8, and Thunderbird 128.8
 - CVE-2025-26695: Downloading of OpenPGP keys from WKD used incorrect padding
 - CVE-2025-26696: Crafted email message incorrectly shown as being encrypted

 Other fixes:
 * Opening an .EML file in profiles with many folders
 could take a long time.
 * Users with many folders experienced poor performance
 when resizing message panes.
 *'Replace' button in compose window was overwritten
 when the window was narrow.
 * Export to mobile did not work when 'Use default
 server' was selected.
 * 'Save Link As' was not working in feed web content.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.8.0~150200.8.203.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.8.0~150200.8.203.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.8.0~150200.8.203.1", rls:"openSUSELeap15.6"))) {
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
