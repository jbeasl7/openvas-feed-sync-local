# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.552471023974102");
  script_cve_id("CVE-2023-5841");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 20:19:43 +0000 (Fri, 09 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-55247f3a4f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-55247f3a4f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-55247f3a4f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262406");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the FEDORA-2024-55247f3a4f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for openexr-3.1.10-5.fc40.

##### **Changelog**

```
* Mon Feb 5 2024 Benjamin A. Beasley <code@musicinmybrain.net> - 3.1.10-5
- Backport proposed fix for CVE-2023-5841 to 3.1.10 (fix RHBZ#2262406)
* Thu Jan 25 2024 Fedora Release Engineering <releng@fedoraproject.org> - 3.1.10-4
- Rebuilt for [link moved to references]
* Sun Jan 21 2024 Fedora Release Engineering <releng@fedoraproject.org> - 3.1.10-3
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'openexr' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~3.1.10~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debuginfo", rpm:"openexr-debuginfo~3.1.10~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-debugsource", rpm:"openexr-debugsource~3.1.10~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-devel", rpm:"openexr-devel~3.1.10~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-libs", rpm:"openexr-libs~3.1.10~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr-libs-debuginfo", rpm:"openexr-libs-debuginfo~3.1.10~5.fc40", rls:"FC40"))) {
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
