# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.97102100109849102");
  script_cve_id("CVE-2023-1732");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-17 17:04:45 +0000 (Wed, 17 May 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-97fd10b49f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-97fd10b49f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-97fd10b49f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165786");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2203758");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-cloudflare-circl' package(s) announced via the FEDORA-2024-97fd10b49f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for golang-github-cloudflare-circl-1.3.7-1.fc41.

##### **Changelog**

```
* Thu Mar 7 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 1.3.7-1
- Update to 1.3.7 - Closes rhbz#2165786 rhbz#2203758
* Sun Feb 11 2024 Maxwell G <maxwell@gtmx.me> - 1.3.1-6
- Rebuild for golang 1.22.0
* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 1.3.1-5
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'golang-github-cloudflare-circl' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-cloudflare-circl", rpm:"golang-github-cloudflare-circl~1.3.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-cloudflare-circl-devel", rpm:"golang-github-cloudflare-circl-devel~1.3.7~1.fc41", rls:"FC41"))) {
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
