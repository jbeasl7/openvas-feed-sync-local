# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.6541310271021000");
  script_cve_id("CVE-2022-41717", "CVE-2022-41723");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 16:36:40 +0000 (Thu, 09 Mar 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-65413f7fd0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-65413f7fd0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-65413f7fd0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163084");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2169567");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178430");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsx' package(s) announced via the FEDORA-2023-65413f7fd0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for dnsx-1.1.5-1.fc40.

##### **Changelog**

```
* Fri Oct 27 2023 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 1.1.5-1
- Update to 1.1.5 - Closes rhbz#2169567 rhbz#2178430 rhbz#2163084

```");

  script_tag(name:"affected", value:"'dnsx' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsx", rpm:"dnsx~1.1.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsx-debuginfo", rpm:"dnsx-debuginfo~1.1.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsx-debugsource", rpm:"dnsx-debugsource~1.1.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-projectdiscovery-dnsx-devel", rpm:"golang-github-projectdiscovery-dnsx-devel~1.1.5~1.fc40", rls:"FC40"))) {
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
