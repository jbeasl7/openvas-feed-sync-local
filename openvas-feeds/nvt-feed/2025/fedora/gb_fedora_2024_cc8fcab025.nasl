# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.99998102999798025");
  script_cve_id("CVE-2022-34038", "CVE-2023-39325", "CVE-2023-44487", "CVE-2023-47108");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-10 19:15:16 +0000 (Fri, 10 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-cc8fcab025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-cc8fcab025");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-cc8fcab025");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170782");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2171486");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225797");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236640");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243321");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248266");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251230");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'etcd' package(s) announced via the FEDORA-2024-cc8fcab025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for etcd-3.5.13-1.fc41.

##### **Changelog**

```
* Tue Apr 16 2024 Mikel Olasagasti Uranga <mikel@olasagasti.info> - 3.5.13-1
- Update to 3.5.13 - Closes rhbz#2225797 rhbz#2171486 rhbz#2170782
 rhbz#2236640 rhbz#2243321 rhbz#2248266 rhbz#2251230
* Tue Apr 16 2024 Pete Zaitcev <zaitcev@kotori.zaitcev.us> - 3.5.11-1
- Update to 3.5.11

```");

  script_tag(name:"affected", value:"'etcd' package(s) on Fedora 41.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"etcd", rpm:"etcd~3.5.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcd-debuginfo", rpm:"etcd-debuginfo~3.5.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"etcd-debugsource", rpm:"etcd-debugsource~3.5.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-etcd-devel", rpm:"golang-etcd-devel~3.5.13~1.fc41", rls:"FC41"))) {
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
