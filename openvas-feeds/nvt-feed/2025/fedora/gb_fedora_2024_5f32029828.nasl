# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.510232029828");
  script_cve_id("CVE-2024-1931");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-17 16:56:50 +0000 (Tue, 17 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-5f32029828)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5f32029828");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-5f32029828");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268404");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268419");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the FEDORA-2024-5f32029828 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for unbound-1.19.3-1.fc41.

##### **Changelog**

```
* Fri Apr 12 2024 Petr Mensik <pemensik@redhat.com> - 1.19.3-1
- Update to 1.19.3 (rhbz#2268404)
- Fix CVE-2024-1931, Denial of service when trimming EDE text on positive
 replies. (rhbz#2268419)
- Use the origin (DNAME) TTL for synthesized CNAMEs as per RFC 6672.
- Bug fixes
* Sat Mar 9 2024 Paul Wouters <paul.wouters@aiven.io> - 1.19.1-4
- Add spec file comment

```");

  script_tag(name:"affected", value:"'unbound' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound-debuginfo", rpm:"python3-unbound-debuginfo~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor", rpm:"unbound-anchor~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-anchor-debuginfo", rpm:"unbound-anchor-debuginfo~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debuginfo", rpm:"unbound-debuginfo~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-debugsource", rpm:"unbound-debugsource~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs-debuginfo", rpm:"unbound-libs-debuginfo~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-munin", rpm:"unbound-munin~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-utils", rpm:"unbound-utils~1.19.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-utils-debuginfo", rpm:"unbound-utils-debuginfo~1.19.3~1.fc41", rls:"FC41"))) {
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
