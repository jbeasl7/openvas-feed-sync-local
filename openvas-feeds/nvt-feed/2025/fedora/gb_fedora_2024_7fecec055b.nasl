# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.7102101991019905598");
  script_cve_id("CVE-2023-48795", "CVE-2023-49568", "CVE-2023-49569");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 11:15:13 +0000 (Fri, 12 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-7fecec055b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7fecec055b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7fecec055b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2214601");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255090");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259808");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259817");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259827");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259832");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-git-5' package(s) announced via the FEDORA-2024-7fecec055b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-git-5-5.12.0-1.fc41.

##### **Changelog**

```
* Tue Apr 23 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 5.12.0-1
- Update to 5.12.0 - Closes rhbz#2214601 rhbz#2255090 rhbz#2259808
 rhbz#2259817 rhbz#2259827 rhbz#2259832

```");

  script_tag(name:"affected", value:"'golang-github-git-5' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-git-5", rpm:"golang-github-git-5~5.12.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-git-5-devel", rpm:"golang-github-git-5-devel~5.12.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-git-5-doc", rpm:"golang-github-git-5-doc~5.12.0~1.fc41", rls:"FC41"))) {
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
