# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1002397079710000");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-d23a07ad00)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d23a07ad00");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d23a07ad00");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2363230");
  script_xref(name:"URL", value:"https://deluge.readthedocs.io/en/deluge-2.2.0/changelog.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'deluge' package(s) announced via the FEDORA-2025-d23a07ad00 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[link moved to references]

2.2.0 (2025-04-28)

Breaking changes

 Removed Python 3.6 support (Python >= 3.7)

Core

 Fix GHSL-2024-189 - insecure HTTP for new version check.

 Fix alert handler segfault.

 Add support for creating v2 torrents.

GTK UI

 Fix changing torrent ownership.

 Fix upper limit of upload/download in Add Torrent dialog.

 Fix #3339 - Resizing window crashes with Piecesbar or Stats plugin.

 Fix #3350 - Unable to use quick search.

 Fix #3598 - Missing AppIndicator option in Preferences.

 Set Appindicator as default for tray icon on Linux.

 Add feature to switch between dark/light themes.

Web UI

 Fix GHSL-2024-191 - potential flag endpoint path traversal.

 Fix GHSL-2024-188 - js script dir traversal vulnerability.

 Fix GHSL-2024-190 - insecure tracker icon endpoint.

 Fix unable to stop daemon in connection manager.

 Fix responsiveness to avoid 'Connection lost'.

 Add support for network interface name as well as IP address.

 Add ability to change UI theme.

Console UI

 Fix 'rm' and 'move' commands hanging when done.

 Fix #3538 - Unable to add host in connection manager.

 Disable interactive-mode on Windows.

UI library

 Fix tracker icon display by converting to png format.

 Fix splitting trackers by newline

 Add clickable URLs for torrent comment and tracker status.

Label

 Fix torrent deletion not removed from config.

 Fix label display name in submenu.

AutoAdd

 Fix #3515 - Torrent file decoding errors disabled watch folder.");

  script_tag(name:"affected", value:"'deluge' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"deluge", rpm:"deluge~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-common", rpm:"deluge-common~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-console", rpm:"deluge-console~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-daemon", rpm:"deluge-daemon~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-gtk", rpm:"deluge-gtk~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-images", rpm:"deluge-images~2.2.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"deluge-web", rpm:"deluge-web~2.2.0~1.fc41", rls:"FC41"))) {
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
