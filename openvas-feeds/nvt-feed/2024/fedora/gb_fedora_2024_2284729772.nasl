# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.2284729772");
  script_cve_id("CVE-2024-47537", "CVE-2024-47538", "CVE-2024-47539", "CVE-2024-47540", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47543", "CVE-2024-47596", "CVE-2024-47600", "CVE-2024-47606", "CVE-2024-47607", "CVE-2024-47613", "CVE-2024-47615", "CVE-2024-47774", "CVE-2024-47775", "CVE-2024-47777", "CVE-2024-47778", "CVE-2024-47835");
  script_tag(name:"creation_date", value:"2024-12-23 04:08:39 +0000 (Mon, 23 Dec 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:57:16 +0000 (Wed, 18 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-2284729772)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2284729772");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2284729772");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331792");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331796");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331813");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331817");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331825");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331863");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331867");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331873");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331888");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331892");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331897");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331901");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331905");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332090");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332092");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332095");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332097");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2332099");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-directxmath, mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good, mingw-orc' package(s) announced via the FEDORA-2024-2284729772 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.24.10, fixes multiple CVEs.");

  script_tag(name:"affected", value:"'mingw-directxmath, mingw-gstreamer1, mingw-gstreamer1-plugins-bad-free, mingw-gstreamer1-plugins-base, mingw-gstreamer1-plugins-good, mingw-orc' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-directxmath", rpm:"mingw-directxmath~3.20~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1", rpm:"mingw-gstreamer1~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-bad-free", rpm:"mingw-gstreamer1-plugins-bad-free~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-base", rpm:"mingw-gstreamer1-plugins-base~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-gstreamer1-plugins-good", rpm:"mingw-gstreamer1-plugins-good~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-orc", rpm:"mingw-orc~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-directxmath", rpm:"mingw32-directxmath~3.20~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1", rpm:"mingw32-gstreamer1~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-debuginfo", rpm:"mingw32-gstreamer1-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free", rpm:"mingw32-gstreamer1-plugins-bad-free~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw32-gstreamer1-plugins-bad-free-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base", rpm:"mingw32-gstreamer1-plugins-base~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-base-debuginfo", rpm:"mingw32-gstreamer1-plugins-base-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good", rpm:"mingw32-gstreamer1-plugins-good~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-gstreamer1-plugins-good-debuginfo", rpm:"mingw32-gstreamer1-plugins-good-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-orc", rpm:"mingw32-orc~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-orc-compiler", rpm:"mingw32-orc-compiler~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-orc-debuginfo", rpm:"mingw32-orc-debuginfo~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-directxmath", rpm:"mingw64-directxmath~3.20~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1", rpm:"mingw64-gstreamer1~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-debuginfo", rpm:"mingw64-gstreamer1-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free", rpm:"mingw64-gstreamer1-plugins-bad-free~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-bad-free-debuginfo", rpm:"mingw64-gstreamer1-plugins-bad-free-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base", rpm:"mingw64-gstreamer1-plugins-base~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-base-debuginfo", rpm:"mingw64-gstreamer1-plugins-base-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good", rpm:"mingw64-gstreamer1-plugins-good~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-gstreamer1-plugins-good-debuginfo", rpm:"mingw64-gstreamer1-plugins-good-debuginfo~1.24.10~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-orc", rpm:"mingw64-orc~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-orc-compiler", rpm:"mingw64-orc-compiler~0.4.40~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-orc-debuginfo", rpm:"mingw64-orc-debuginfo~0.4.40~1.fc40", rls:"FC40"))) {
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
