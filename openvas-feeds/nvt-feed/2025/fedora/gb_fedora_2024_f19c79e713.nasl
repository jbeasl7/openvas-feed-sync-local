# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.102199979101713");
  script_cve_id("CVE-2023-52356", "CVE-2023-6228", "CVE-2024-7006");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-13 15:14:35 +0000 (Tue, 13 Aug 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-f19c79e713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f19c79e713");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f19c79e713");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251863");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260112");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302997");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the FEDORA-2024-f19c79e713 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libtiff-4.6.0-6.fc41.

##### **Changelog**

```
* Wed Aug 14 2024 Michal Hlavinka <mhlavink@redhat.com> - 4.6.0-6
- fix CVE-2024-7006 (rhbz#2302997)
- fix CVE-2023-52356 (rhbz#2260112)
- fix CVE-2023-6228 (rhbz#2251863)

```");

  script_tag(name:"affected", value:"'libtiff' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-debugsource", rpm:"libtiff-debugsource~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-tools", rpm:"libtiff-tools~4.6.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-tools-debuginfo", rpm:"libtiff-tools-debuginfo~4.6.0~6.fc41", rls:"FC41"))) {
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
