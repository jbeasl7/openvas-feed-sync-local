# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.1157.1");
  script_cve_id("CVE-2025-3028", "CVE-2025-3029", "CVE-2025-3030");
  script_tag(name:"creation_date", value:"2025-04-09 04:06:03 +0000 (Wed, 09 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:1157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1157-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251157-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240083");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038923.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:1157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

- Mozilla Thunderbird ESR 128.9 MFSA 2025-24 (bsc#1240083)
 * CVE-2025-3028: Use-after-free triggered by XSLTProcessor
 * CVE-2025-3029: URL Bar Spoofing via non-BMP Unicode characters
 * CVE-2025-3030: Memory safety bugs fixed in Firefox 137, Thunderbird 137,
 Firefox ESR 128.9, and Thunderbird 128.9

Other fixes:

 * new: Thunderbird now has a notification system for real-time
 desktop alerts
 * fixed: Data corruption occurred when compacting IMAP Drafts
 folder after saving a message
 * fixed: Right-clicking 'Decrypt and Save As...' on an
 attachment file failed.
 * fixed: Thunderbird could crash when importing mail
 * fixed: Sort indicators were missing on the calendar events
 list.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.9.0~150200.8.206.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.9.0~150200.8.206.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.9.0~150200.8.206.1", rls:"openSUSELeap15.6"))) {
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
