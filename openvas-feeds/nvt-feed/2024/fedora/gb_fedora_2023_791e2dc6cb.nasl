# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.79110121009969998");
  script_cve_id("CVE-2022-41717");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 17:50:12 +0000 (Mon, 12 Dec 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-791e2dc6cb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-791e2dc6cb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-791e2dc6cb");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2051033");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163111");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-colinmarc-hdfs-2' package(s) announced via the FEDORA-2023-791e2dc6cb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-colinmarc-hdfs-2-2.4.0-1.fc40.

##### **Changelog**

```
* Thu Oct 12 2023 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 2.4.0-1
- Update to 2.4.0 - Closes rhbz#2051033 rhbz#2163111

```");

  script_tag(name:"affected", value:"'golang-github-colinmarc-hdfs-2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-colinmarc-hdfs-2", rpm:"golang-github-colinmarc-hdfs-2~2.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-colinmarc-hdfs-2-debuginfo", rpm:"golang-github-colinmarc-hdfs-2-debuginfo~2.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-colinmarc-hdfs-2-debugsource", rpm:"golang-github-colinmarc-hdfs-2-debugsource~2.4.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-colinmarc-hdfs-2-devel", rpm:"golang-github-colinmarc-hdfs-2-devel~2.4.0~1.fc40", rls:"FC40"))) {
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
