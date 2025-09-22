# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.739899798410098");
  script_cve_id("CVE-2020-36627");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 15:13:29 +0000 (Thu, 05 Jan 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-7398c7b4db)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7398c7b4db");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7398c7b4db");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2113331");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2156669");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-macaron-inject' package(s) announced via the FEDORA-2023-7398c7b4db advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-macaron-inject-0-0.19.20210110git138e592.fc39.

##### **Changelog**

```
* Tue Jul 11 2023 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 0-0.19
- Fix FTBFS rhbz#2113331 rhbz#2156669
* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 0-0.18
- Rebuilt for [link moved to references]
* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 0-0.17
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'golang-github-macaron-inject' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-macaron-inject", rpm:"golang-github-macaron-inject~0~0.19.20210110git138e592.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-macaron-inject-devel", rpm:"golang-github-macaron-inject-devel~0~0.19.20210110git138e592.fc39", rls:"FC39"))) {
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
