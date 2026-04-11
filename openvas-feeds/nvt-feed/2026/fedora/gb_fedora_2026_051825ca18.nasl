# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.051825999718");
  script_cve_id("CVE-2026-35538", "CVE-2026-35539", "CVE-2026-35540", "CVE-2026-35541", "CVE-2026-35542", "CVE-2026-35543", "CVE-2026-35544", "CVE-2026-35545");
  script_tag(name:"creation_date", value:"2026-04-09 04:50:45 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-07 20:37:57 +0000 (Tue, 07 Apr 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-051825ca18)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-051825ca18");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-051825ca18");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2454784");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2454786");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2454793");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'roundcubemail' package(s) announced via the FEDORA-2026-051825ca18 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 1.6.15**

This is a security update to the stable version 1.6 of Roundcube Webmail.
It provides fixes to some regressions introduced in the previous release as well a recently reported security vulnerability:

- SVG Animate FUNCIRI Attribute Bypass -- Remote Image Loading via fill/filter/stroke, reported by class_nzm.

This version is considered stable and we recommend to update all productive installations of Roundcube 1.6.x with it. Please do backup your data before updating!

CHANGELOG

- Fix regression where mail search would fail on non-ascii search criteria (#10121)
- Fix regression where some data url images could get ignored/lost (#10128)
- Fix SVG Animate FUNCIRI Attribute Bypass -- Remote Image Loading via fill/filter/stroke");

  script_tag(name:"affected", value:"'roundcubemail' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"roundcubemail", rpm:"roundcubemail~1.6.15~1.fc42", rls:"FC42"))) {
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
