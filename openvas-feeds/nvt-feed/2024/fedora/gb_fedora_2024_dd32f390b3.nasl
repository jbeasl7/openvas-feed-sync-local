# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10010032102390983");
  script_cve_id("CVE-2024-1753");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-dd32f390b3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-dd32f390b3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-dd32f390b3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265513");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270124");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the FEDORA-2024-dd32f390b3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-1753

Automatic update for podman-4.9.4-1.fc39.

##### **Changelog for podman**

```
* Mon Mar 25 2024 Packit <hello@packit.dev> - 5:4.9.4-1
- [packit] 4.9.4 upstream release

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:4.9.3-5
- Show the toolbox RPMs used to run the tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:4.9.3-4
- Avoid running out of storage space when running the Toolbx tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:4.9.3-3
- Silence warnings about deprecated grep(1) use in test logs

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:4.9.3-2
- Update how Toolbx is spelt

```");

  script_tag(name:"affected", value:"'podman' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debugsource", rpm:"podman-debugsource~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-plugins", rpm:"podman-plugins~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-plugins-debuginfo", rpm:"podman-plugins-debuginfo~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests", rpm:"podman-tests~4.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~4.9.4~1.fc39", rls:"FC39"))) {
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
