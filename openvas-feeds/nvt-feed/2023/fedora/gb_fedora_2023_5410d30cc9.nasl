# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885188");
  script_cve_id("CVE-2022-34300");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:41 +0000 (Sun, 05 Nov 2023)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-29 22:14:24 +0000 (Wed, 29 Jun 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-5410d30cc9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5410d30cc9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5410d30cc9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177897");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221163");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233637");
  script_xref(name:"URL", value:"https://godotengine.org/article/godot-4-1-is-here/");
  script_xref(name:"URL", value:"https://godotengine.org/article/maintenance-release-godot-4-1-1/");
  script_xref(name:"URL", value:"https://godotengine.org/article/maintenance-release-godot-4-1-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'godot' package(s) announced via the FEDORA-2023-5410d30cc9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updates provides Godot 4.1.2 as the latest stable release for this free and open source game engine.

It fixes many bugs, improves features and usability.

For Fedora 37 and 38, it updates from Godot 4.0.x to 4.1.x, so the release notes for the minor 4.1 release are worth reviewing.

This update also improves the .blend file import integration by pre-filling the path to system packaged Blender.
It also fixes a security vulnerability in the EXR importer.

Release notes:
- [links moved to references]");

  script_tag(name:"affected", value:"'godot' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"godot", rpm:"godot~4.1.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"godot-debuginfo", rpm:"godot-debuginfo~4.1.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"godot-debugsource", rpm:"godot-debugsource~4.1.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"godot-runner", rpm:"godot-runner~4.1.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"godot-runner-debuginfo", rpm:"godot-runner-debuginfo~4.1.2~1.fc39", rls:"FC39"))) {
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
