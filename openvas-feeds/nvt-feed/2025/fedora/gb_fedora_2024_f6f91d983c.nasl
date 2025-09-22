# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10261029110098399");
  script_cve_id("CVE-2024-28180", "CVE-2024-6104");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-f6f91d983c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f6f91d983c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f6f91d983c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009869");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171504");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225838");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268886");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294003");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_41_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-acme-lego' package(s) announced via the FEDORA-2024-f6f91d983c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-acme-lego-4.17.4-4.fc41.

##### **Changelog**

```
* Mon Jul 29 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 4.17.4-4
- Update to 4.17.4 - Closes rhbz#2009869 rhbz#2171504 rhbz#2268886
 rhbz#2294003 rhbz#2225838
* Mon Jul 29 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 4.17.4-3
- Update to 4.17.4 - Closes rhbz#2009869 rhbz#2171504 rhbz#2268886
 rhbz#2294003 rhbz#2225838
* Mon Jul 29 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 4.17.4-2
- Update to 4.17.4 - Closes rhbz#2009869 rhbz#2171504 rhbz#2268886
 rhbz#2294003 rhbz#2225838
* Mon Jul 29 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 4.17.4-1
- Update to 4.17.4 - Closes rhbz#2009869 rhbz#2171504 rhbz#2268886
 rhbz#2294003 rhbz#2225838
* Thu Jul 18 2024 Fedora Release Engineering <releng@fedoraproject.org> - 4.4.0-16
- Rebuilt for [link moved to references]
* Sun Feb 11 2024 Maxwell G <maxwell@gtmx.me> - 4.4.0-15
- Rebuild for golang 1.22.0
* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 4.4.0-14
- Rebuilt for [link moved to references]
* Fri Jan 19 2024 Fedora Release Engineering <releng@fedoraproject.org> - 4.4.0-13
- Rebuilt for [link moved to references]
* Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 4.4.0-11
- Rebuilt for [link moved to references]
* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 4.4.0-10
- Rebuilt for [link moved to references]
* Wed Aug 10 2022 Maxwell G <gotmax@e.email> - 4.4.0-9
- Rebuild to fix FTBFS

```");

  script_tag(name:"affected", value:"'golang-github-acme-lego' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-acme-lego-4-devel", rpm:"compat-golang-github-acme-lego-4-devel~4.17.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-golang-github-xenolf-lego-devel", rpm:"compat-golang-github-xenolf-lego-devel~4.17.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-acme-lego", rpm:"golang-github-acme-lego~4.17.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-acme-lego-debuginfo", rpm:"golang-github-acme-lego-debuginfo~4.17.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-acme-lego-debugsource", rpm:"golang-github-acme-lego-debugsource~4.17.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-acme-lego-devel", rpm:"golang-github-acme-lego-devel~4.17.4~4.fc41", rls:"FC41"))) {
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
