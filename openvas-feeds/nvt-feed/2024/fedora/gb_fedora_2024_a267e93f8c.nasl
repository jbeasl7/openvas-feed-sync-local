# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886332");
  script_cve_id("CVE-2024-1753");
  script_tag(name:"creation_date", value:"2024-03-27 02:16:13 +0000 (Wed, 27 Mar 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 15:15:41 +0000 (Mon, 18 Mar 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-a267e93f8c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a267e93f8c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-a267e93f8c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265513");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269148");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270124");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containers-common, netavark, podman' package(s) announced via the FEDORA-2024-a267e93f8c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-1753

Automatic update for podman-5.0.0-1.fc40.

##### **Changelog for podman**

```
* Tue Mar 19 2024 Packit <hello@packit.dev> - 5:5.0.0-1
- [packit] 5.0.0 upstream release

* Fri Mar 15 2024 Packit <hello@packit.dev> - 5:5.0.0~rc7-1
- [packit] 5.0.0-rc7 upstream release

* Wed Mar 13 2024 Lokesh Mandvekar <lsm5@redhat.com> - 5:5.0.0~rc6-2
- Resolves: #2269148 - make passt a hard dep

* Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
- [packit] 5.0.0-rc6 upstream release

* Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
- [packit] 5.0.0-rc5 upstream release

* Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
- [packit] 5.0.0-rc4 upstream release

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
- Show the toolbox RPMs used to run the tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
- Avoid running out of storage space when running the Toolbx tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
- Silence warnings about deprecated grep(1) use in test logs

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
- Update how Toolbx is spelt

* Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
- [packit] 5.0.0-rc3 upstream release

```

----

Automatic update for podman-5.0.0~rc7-1.fc40.

##### **Changelog for podman**

```
* Fri Mar 15 2024 Packit <hello@packit.dev> - 5:5.0.0~rc7-1
- [packit] 5.0.0-rc7 upstream release

* Wed Mar 13 2024 Lokesh Mandvekar <lsm5@redhat.com> - 5:5.0.0~rc6-2
- Resolves: #2269148 - make passt a hard dep

* Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
- [packit] 5.0.0-rc6 upstream release

* Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
- [packit] 5.0.0-rc5 upstream release

* Tue Mar 05 2024 Packit <hello@packit.dev> - 5:5.0.0~rc4-1
- [packit] 5.0.0-rc4 upstream release

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-5
- Show the toolbox RPMs used to run the tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-4
- Avoid running out of storage space when running the Toolbx tests

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-3
- Silence warnings about deprecated grep(1) use in test logs

* Fri Mar 01 2024 Debarshi Ray <rishi@fedoraproject.org> - 5:5.0.0~rc3-2
- Update how Toolbx is spelt

* Thu Feb 22 2024 Packit <hello@packit.dev> - 5:5.0.0~rc3-1
- [packit] 5.0.0-rc3 upstream release

```



----

make passt and netavark hard dependencies for podman

----

Automatic update for podman-5.0.0~rc6-1.fc40.

##### **Changelog for podman**

```
* Mon Mar 11 2024 Packit <hello@packit.dev> - 5:5.0.0~rc6-1
- [packit] 5.0.0-rc6 upstream release

* Fri Mar 08 2024 Packit <hello@packit.dev> - 5:5.0.0~rc5-1
- [packit] 5.0.0-rc5 upstream release

* Tue Mar 05 2024 Packit <hello@packit.dev> - ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'containers-common, netavark, podman' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"containers-common", rpm:"containers-common~0.58.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containers-common-extra", rpm:"containers-common-extra~0.58.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netavark", rpm:"netavark~1.10.3~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netavark-debuginfo", rpm:"netavark-debuginfo~1.10.3~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netavark-debugsource", rpm:"netavark-debugsource~1.10.3~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debugsource", rpm:"podman-debugsource~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests", rpm:"podman-tests~5.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~5.0.0~1.fc40", rls:"FC40"))) {
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
