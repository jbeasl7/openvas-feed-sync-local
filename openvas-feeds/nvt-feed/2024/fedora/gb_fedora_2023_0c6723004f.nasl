# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.0996723004102");
  script_cve_id("CVE-2022-21698");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 02:59:10 +0000 (Thu, 24 Feb 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-0c6723004f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-0c6723004f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-0c6723004f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2067400");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-alertmanager' package(s) announced via the FEDORA-2023-0c6723004f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-prometheus-alertmanager-0.23.0-15.fc39.

##### **Changelog**

```
* Sat Apr 29 2023 Sergio M. Basto <sergio@serjux.com> - 0.23.0-15
- Include s390x, and disable tests because it is failing
* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 0.23.0-14
- Rebuilt for [link moved to references]
* Wed Aug 10 2022 Maxwell G <gotmax@e.email> - 0.23.0-13
- Rebuild to fix FTBFS
* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 0.23.0-12
- Rebuilt for [link moved to references]
* Tue Jul 19 2022 Maxwell G <gotmax@e.email> - 0.23.0-11
- Rebuild for
 CVE-2022-{1705,32148,30631,30633,28131,30635,30632,30630,1962} in golang
* Thu Jun 23 2022 Maxwell G <gotmax@e.email> - 0.23.0-10
- Rebuild to mitigate CVE-2022-21698 (rhbz#2067400).

```");

  script_tag(name:"affected", value:"'golang-github-prometheus-alertmanager' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.23.0~15.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debuginfo", rpm:"golang-github-prometheus-alertmanager-debuginfo~0.23.0~15.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debugsource", rpm:"golang-github-prometheus-alertmanager-debugsource~0.23.0~15.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-devel", rpm:"golang-github-prometheus-alertmanager-devel~0.23.0~15.fc39", rls:"FC39"))) {
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
