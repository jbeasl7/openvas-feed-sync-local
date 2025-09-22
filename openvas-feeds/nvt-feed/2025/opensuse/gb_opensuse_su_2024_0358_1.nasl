# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0358.1");
  script_cve_id("CVE-2024-51774");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-04 14:27:25 +0000 (Mon, 04 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0358-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0358-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EAPEFFISOQ6DXWX2VVALFRSBJ6TO56JQ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232731");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qbittorrent' package(s) announced via the openSUSE-SU-2024:0358-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qbittorrent fixes the following issues:

- Update to version 5.0.1 (fixes boo#1232731 CVE-2024-51774)

 Added features:

 * Add 'Simple pread/pwrite' disk IO type

 Bug fixes:

 * Don't ignore SSL errors (boo#1232731 CVE-2024-51774)
 * Don't try to apply Mark-of-the-Web to nonexistent files
 * Disable 'Move to trash' option by default
 * Disable the ability to create torrents with a piece size of
 256MiB
 * Allow to choose Qt style
 * Always notify user about duplicate torrent
 * Correctly handle 'torrent finished after move' event
 * Correctly apply filename filter when `!qB` extension is
 enabled
 * Improve color scheme change detection
 * Fix button state for SSL certificate check

 Web UI:

 * Fix CSS that results in hidden torrent list in some browsers
 * Use proper text color to highlight items in all filter lists
 * Fix 'rename files' dialog cannot be opened more than once
 * Fix UI of Advanced Settings to show all settings
 * Free resources allocated by web session once it is destructed

 Search:

 * Import correct libraries

 Other changes:

 * Sync flag icons with upstream");

  script_tag(name:"affected", value:"'qbittorrent' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"qbittorrent", rpm:"qbittorrent~5.0.1~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qbittorrent-nox", rpm:"qbittorrent-nox~5.0.1~bp156.3.6.1", rls:"openSUSELeap15.6"))) {
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
