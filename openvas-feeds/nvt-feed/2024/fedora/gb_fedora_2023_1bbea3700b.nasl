# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.1989810197370098");
  script_cve_id("CVE-2022-23515", "CVE-2022-23516");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 17:14:37 +0000 (Mon, 19 Dec 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-1bbea3700b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1bbea3700b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-1bbea3700b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2126896");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153235");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153242");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153263");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-loofah' package(s) announced via the FEDORA-2023-1bbea3700b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for rubygem-loofah-2.22.0-1.fc40.

##### **Changelog**

```
* Thu Nov 23 2023 Vit Ondruch <vondruch@redhat.com> - 2.22.0-1
- Update to Loofah 2.22.0.
 Resolves: rhbz#2126896
 Resolves: rhbz#2153235
 Resolves: rhbz#2153242
 Resolves: rhbz#2153263

```");

  script_tag(name:"affected", value:"'rubygem-loofah' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-loofah", rpm:"rubygem-loofah~2.22.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-loofah-doc", rpm:"rubygem-loofah-doc~2.22.0~1.fc40", rls:"FC40"))) {
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
