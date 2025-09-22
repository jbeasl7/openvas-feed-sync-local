# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.46999510129957");
  script_cve_id("CVE-2022-1996", "CVE-2022-23524", "CVE-2022-23526", "CVE-2022-41717");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-46c95e2c57)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-46c95e2c57");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-46c95e2c57");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1971029");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1971091");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1977738");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2045644");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097975");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2138841");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142198");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142210");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155938");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2155939");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163231");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-helm-3' package(s) announced via the FEDORA-2023-46c95e2c57 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-helm-3-3.11.1-1.fc39.

##### **Changelog**

```
* Tue Feb 21 2023 Davide Cavalca <dcavalca@fedoraproject.org> - 3.11.1-1
- Update to 3.11.1, Fixes: RHBZ#1977738, RHBZ#2045644, RHBZ#2138841,
 RHBZ#2142198, RHBZ#2142210, RHBZ#2097975, RHBZ#2155938, RHBZ#2155939,
 RHBZ#2163231, RHBZ#1971091, RHBZ#1971029
* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 3.5.4-8
- Rebuilt for [link moved to references]
* Wed Aug 10 2022 Maxwell G <gotmax@e.email> - 3.5.4-7
- Rebuild to fix FTBFS
* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 3.5.4-6
- Rebuilt for [link moved to references]
* Tue Jul 19 2022 Maxwell G <gotmax@e.email> - 3.5.4-5
- Rebuild for CVE-2022-{1705,32148,30631,30633,28131,30635,30632,30630,1962} in
 golang
* Sat Jul 9 2022 Maxwell G <gotmax@e.email> - 3.5.4-4
- Rebuild for CVE-2022-{24675,28327,29526 in golang}
* Thu Jan 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 3.5.4-3
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'golang-helm-3' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-helm-3", rpm:"golang-helm-3~3.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-helm-3-debugsource", rpm:"golang-helm-3-debugsource~3.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-helm-3-devel", rpm:"golang-helm-3-devel~3.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm", rpm:"helm~3.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helm-debuginfo", rpm:"helm-debuginfo~3.11.1~1.fc39", rls:"FC39"))) {
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
