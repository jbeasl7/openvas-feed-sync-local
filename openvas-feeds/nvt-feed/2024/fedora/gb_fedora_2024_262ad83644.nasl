# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885693");
  script_cve_id("CVE-2023-22467");
  script_tag(name:"creation_date", value:"2024-02-13 02:03:08 +0000 (Tue, 13 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-11 03:09:58 +0000 (Wed, 11 Jan 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-262ad83644)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-262ad83644");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-262ad83644");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2159961");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257774");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-nikola' package(s) announced via the FEDORA-2024-262ad83644 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to the latest stable version:

Features
--------

* Implement a new plugin manager from scratch to replace Yapsy,
 which does not work on Python 3.12 due to Python 3.12 carelessly
 removing parts of the standard library (Issue #3719)
* Support for Discourse as comment system (Issue #3689)

Bugfixes
--------

* Fix loading of templates from plugins with ``__init__.py`` files
 (Issue #3725)
* Fix margins of paragraphs at the end of sections (Issue #3704)
* Ignore ``.DS_Store`` files in listing indexes (Issue #3698)
* Fix baguetteBox.js invoking in the base theme (Issue #3687)
* Fix development (preview) server ``nikola auto``
 for non-root SITE_URL, in particular when URL_TYPE is full_path.
 (Issue #3715)");

  script_tag(name:"affected", value:"'python-nikola' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"nikola", rpm:"nikola~8.3.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-nikola", rpm:"python-nikola~8.3.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-nikola-doc", rpm:"python-nikola-doc~8.3.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nikola", rpm:"python3-nikola~8.3.0~1.fc39", rls:"FC39"))) {
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
