# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856574");
  script_cve_id("CVE-2024-8900", "CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9396", "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400", "CVE-2024-9401", "CVE-2024-9402", "CVE-2024-9680");
  script_tag(name:"creation_date", value:"2024-10-16 04:02:48 +0000 (Wed, 16 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 15:07:36 +0000 (Wed, 16 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3629-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243629-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231413");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019602.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:3629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Update to Mozilla Thunderbird 128.3.1 (MFSA 2024-51, bsc#1231413):

- CVE-2024-9680: Use-after-free in Animation timeline

Update to Mozilla Thunderbird 128.3 (MFSA 2024-49, bsc#1230979):

- CVE-2024-9392: Compromised content process can bypass site isolation
- CVE-2024-9393: Cross-origin access to PDF contents through multipart responses
- CVE-2024-9394: Cross-origin access to JSON contents through multipart responses
- CVE-2024-8900: Clipboard write permission bypass
- CVE-2024-9396: Potential memory corruption may occur when cloning certain objects
- CVE-2024-9397: Potential directory upload bypass via clickjacking
- CVE-2024-9398: External protocol handlers could be enumerated via popups
- CVE-2024-9399: Specially crafted WebTransport requests could lead to denial of service
- CVE-2024-9400: Potential memory corruption during JIT compilation
- CVE-2024-9401: Memory safety bugs fixed in Firefox 131, Firefox ESR 115.16, Firefox ESR 128.3, Thunderbird 131, and Thunderbird 128.3
- CVE-2024-9402: Memory safety bugs fixed in Firefox 131, Firefox ESR 128.3, Thunderbird 131, and Thunderbird 128.3

Other fixes:

- fixed: Opening an EML file with a 'mailto:' link did not work
- fixed: Collapsed POP3 account folder was expanded after emptying trash on exit
- fixed: 'Mark Folder Read' on a cross-folder search marked all underlying folders read
- fixed: Unable to open/view attached OpenPGP encrypted messages
- fixed: Unable to 'Decrypt and Open' an attached OpenPGP key file
- fixed: Subject could disappear when replying to a message saved in an EML file
- fixed: OAuth2 authentication method was not available when adding SMTP server
- fixed: Unable to subscribe to .ics calendars in some situations
- fixed: Visual and UX improvements");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.3.0~150200.8.182.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.3.0~150200.8.182.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.3.0~150200.8.182.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.3.0~150200.8.182.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.3.0~150200.8.182.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.3.0~150200.8.182.1", rls:"openSUSELeap15.6"))) {
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
