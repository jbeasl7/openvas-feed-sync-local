# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.0106837085");
  script_cve_id("CVE-2025-11494", "CVE-2025-11495", "CVE-2025-69644", "CVE-2025-69645", "CVE-2025-69646", "CVE-2026-2341", "CVE-2026-3441", "CVE-2026-3442");
  script_tag(name:"creation_date", value:"2026-03-16 04:56:17 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-20 18:23:46 +0000 (Fri, 20 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-0106837085)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-0106837085");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-0106837085");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402843");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402846");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2434680");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438918");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2443834");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445276");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445281");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445284");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'insight' package(s) announced via the FEDORA-2026-0106837085 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream snapshot.
Fixes CVEs 2025-11494, 2025-11495, 2026-2341, 2026-3441, 2026-3442.
Fixes CVEs 2025-69644, 2025-69645, 2025-69646.
Fixes FTBFS.
Relax BR of itcl/itk/iwidgets.
Patch 'libtool_tag' to force C++ language tagging in libtool.");

  script_tag(name:"affected", value:"'insight' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"insight", rpm:"insight~18.0.50.20260306~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"insight-debuginfo", rpm:"insight-debuginfo~18.0.50.20260306~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"insight-debugsource", rpm:"insight-debugsource~18.0.50.20260306~1.fc43", rls:"FC43"))) {
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
