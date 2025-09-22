# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.99498597100917");
  script_cve_id("CVE-2023-3978");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-07 18:24:33 +0000 (Mon, 07 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-c4b597d917)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c4b597d917");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c4b597d917");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2229595");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2234429");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-onsi-ginkgo-2' package(s) announced via the FEDORA-2023-c4b597d917 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-onsi-ginkgo-2-2.12.1-1.fc40.

##### **Changelog**

```
* Sun Sep 24 2023 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 2.12.1-1
- Update to 2.12.1 - Closes rhbz#2234429 rhbz#2229595

```");

  script_tag(name:"affected", value:"'golang-github-onsi-ginkgo-2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-onsi-ginkgo-2", rpm:"golang-github-onsi-ginkgo-2~2.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-onsi-ginkgo-2-debuginfo", rpm:"golang-github-onsi-ginkgo-2-debuginfo~2.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-onsi-ginkgo-2-debugsource", rpm:"golang-github-onsi-ginkgo-2-debugsource~2.12.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-onsi-ginkgo-2-devel", rpm:"golang-github-onsi-ginkgo-2-devel~2.12.1~1.fc40", rls:"FC40"))) {
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
