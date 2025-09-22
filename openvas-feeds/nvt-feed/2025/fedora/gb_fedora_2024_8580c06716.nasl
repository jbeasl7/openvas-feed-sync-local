# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.85809906716");
  script_cve_id("CVE-2023-39325");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-31 18:05:45 +0000 (Tue, 31 Oct 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8580c06716)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8580c06716");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8580c06716");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064711");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248329");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260773");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261192");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-prometheus-alertmanager' package(s) announced via the FEDORA-2024-8580c06716 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-prometheus-alertmanager-0.27.0-1.fc41.

##### **Changelog**

```
* Thu Apr 18 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 0.27.0-1
- Update to 0.27.0 - Closes rhbz#2064711 rhbz#2248329 rhbz#2260773
 rhbz#2261192
* Sun Feb 11 2024 Maxwell G <maxwell@gtmx.me> - 0.23.0-20
- Rebuild for golang 1.22.0
* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 0.23.0-19
- Rebuilt for [link moved to references]
* Sat Jan 20 2024 Fedora Release Engineering <releng@fedoraproject.org> - 0.23.0-18
- Rebuilt for [link moved to references]
* Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 0.23.0-16
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'golang-github-prometheus-alertmanager' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager", rpm:"golang-github-prometheus-alertmanager~0.27.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debuginfo", rpm:"golang-github-prometheus-alertmanager-debuginfo~0.27.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-debugsource", rpm:"golang-github-prometheus-alertmanager-debugsource~0.27.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-prometheus-alertmanager-devel", rpm:"golang-github-prometheus-alertmanager-devel~0.27.0~1.fc41", rls:"FC41"))) {
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
