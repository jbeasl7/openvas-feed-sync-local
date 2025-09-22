# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887385");
  script_cve_id("CVE-2024-1062", "CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_tag(name:"creation_date", value:"2024-08-15 04:04:18 +0000 (Thu, 15 Aug 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-28 13:15:11 +0000 (Tue, 28 May 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-ac07913be8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ac07913be8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ac07913be8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261879");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2261884");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267976");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274401");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283631");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283632");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292104");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292109");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the FEDORA-2024-ac07913be8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"##### **Changelog**

```
* Tue Jul 30 2024 Viktor Ashirov <vashirov@redhat.com> - 3.0.4-2
- Replace lmdb with lmdb-libs in Requires

* Tue Jul 30 2024 Viktor Ashirov <vashirov@redhat.com> - 3.0.4-1
- Update to 3.0.4
- Resolves: CVE-2024-1062 (rhbz#2261884)
- Resolves: CVE-2024-2199 (rhbz#2283632)
- Resolves: CVE-2024-3657 (rhbz#2283631)
- Resolves: CVE-2024-5953 (rhbz#2292109)
```");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-debugsource", rpm:"389-ds-base-debugsource~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs-debuginfo", rpm:"389-ds-base-libs-debuginfo~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-snmp-debuginfo", rpm:"389-ds-base-snmp-debuginfo~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-389-ds", rpm:"cockpit-389-ds~3.0.4~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lib389", rpm:"python3-lib389~3.0.4~2.fc40", rls:"FC40"))) {
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
