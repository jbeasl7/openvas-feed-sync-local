# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.98290319779797");
  script_cve_id("CVE-2022-1996", "CVE-2022-24675", "CVE-2022-27191", "CVE-2022-28327", "CVE-2022-29526", "CVE-2022-30629", "CVE-2022-41717");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-b29031a7aa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b29031a7aa");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b29031a7aa");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2113146");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163065");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165257");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chisel' package(s) announced via the FEDORA-2023-b29031a7aa advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for chisel-1.9.0-1.fc40.

##### **Changelog**

```
* Sun Aug 20 2023 Filipe Rosset <rosset.filipe@gmail.com> - 1.9.0-1
- Update to 1.9.0 fixes rhbz#2113146 rhbz#2163065 rhbz#2165257
* Wed Jul 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1.7.7-7
- Rebuilt for [link moved to references]
* Wed Jan 18 2023 Fedora Release Engineering <releng@fedoraproject.org> - 1.7.7-6
- Rebuilt for [link moved to references]
* Wed Jul 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 1.7.7-5
- Rebuilt for [link moved to references]
* Tue Jul 19 2022 Maxwell G <gotmax@e.email> - 1.7.7-4
- Rebuild for CVE-2022-{1705,32148,30631,30633,28131,30635,30632,30630,1962} in
 golang
* Fri Jun 17 2022 Robert-Andre Mauchin <zebob.m@gmail.com> - 1.7.7-3
- Rebuilt for CVE-2022-1996, CVE-2022-24675, CVE-2022-28327, CVE-2022-27191,
 CVE-2022-29526, CVE-2022-30629

```");

  script_tag(name:"affected", value:"'chisel' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"chisel", rpm:"chisel~1.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chisel-debuginfo", rpm:"chisel-debuginfo~1.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chisel-debugsource", rpm:"chisel-debugsource~1.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-jpillora-chisel-devel", rpm:"golang-github-jpillora-chisel-devel~1.9.0~1.fc40", rls:"FC40"))) {
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
