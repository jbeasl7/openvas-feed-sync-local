# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.3256575102998");
  script_cve_id("CVE-2022-24785", "CVE-2022-31129");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 14:34:50 +0000 (Thu, 14 Jul 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-3256575fc8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-3256575fc8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-3256575fc8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1990615");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992573");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2004590");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2023994");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039905");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2045852");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2062405");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2075263");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2181597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184443");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224039");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-notebook' package(s) announced via the FEDORA-2023-3256575fc8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for python-notebook-7.0.0-1.fc39.

##### **Changelog**

```
* Thu Jul 20 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0-1
- Update to 7.0.0 (rhbz#2224039)
* Mon Jul 10 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0rc2-1
- Update to 7.0.0 RC2
* Mon Jul 10 2023 Miro Hroncok <miro@hroncok.cz> - 7.0.0b3-3
- Workaround a possible Python 3.12 regression in importlib.resources
* Tue Jul 4 2023 Python Maint <python-maint@redhat.com> - 7.0.0b3-2
- Rebuilt for Python 3.12
* Thu Jun 1 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0b3-1
- Update to 7.0.0 beta 3 (rhbz#2184443)
* Wed Mar 29 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a18-1
- Update to 7.0.0a18 (rhbz#2181597)
* Wed Mar 22 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a17-1
- Update to 7.0.0 alpha 17 (rhbz#2178583)
* Fri Mar 10 2023 Lumir Balhar <lbalhar@redhat.com> - 7.0.0a15-1
- Update to 7.0.0a15
* Mon Mar 6 2023 Lumir Balhar <lbalhar@redhat.com> - 6.5.3-1
- Update to 6.5.3 (rhbz#2062405)
* Wed Feb 1 2023 Lumir Balhar <lbalhar@redhat.com> - 6.5.2-1
- Update to 6.5.2 (#2062405)
* Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.12-2
- Rebuilt for [link moved to references]
* Wed Aug 3 2022 Karolina Surma <ksurma@redhat.com> - 6.4.12-1
- Update to 6.4.12
* Fri Jul 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.11-4
- Rebuilt for [link moved to references]
* Wed Jul 13 2022 Miro Hroncok <mhroncok@redhat.com> - 6.4.11-3
- Fix CVE-2022-24785 and CVE-2022-31129 in bundled moment
- Fixes: rhbz#2075263
* Thu Jun 16 2022 Python Maint <python-maint@redhat.com> - 6.4.11-2
- Rebuilt for Python 3.11
* Mon May 30 2022 Miro Hroncok <mhroncok@redhat.com> - 6.4.11-1
- Update to 6.4.11
* Tue Mar 22 2022 Miro Hroncok <mhroncok@redhat.com> - 6.4.10-1
- Update to 6.4.10
* Tue Jan 25 2022 Miro Hroncok <mhroncok@redhat.com> - 6.4.8-1
- Update to 6.4.8
- Fixes: rhbz#2045852
* Tue Jan 25 2022 Miro Hroncok <mhroncok@redhat.com> - 6.4.7-1
- Update to 6.4.7
- Fixes: rhbz#2039905
* Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.6-3
- Rebuilt for [link moved to references]
* Mon Nov 29 2021 Karolina Surma <ksurma@redhat.com> - 6.4.6-2
- Remove -s from Python shebang in `jupyter-*` executables
 to let Jupyter see pip installed extensions
* Wed Nov 24 2021 Karolina Surma <ksurma@redhat.com> - 6.4.6-1
- Update to 6.4.6
Resolves: rhbz#2023994
* Tue Oct 26 2021 Lumir Balhar <lbalhar@redhat.com> - 6.4.5-1
- Update to 6.4.5
Resolves: rhbz#2004590
* Wed Aug 11 2021 Tomas Hrnciar <thrnciar@redhat.com> - 6.4.3-1
- Update to 6.4.3
- Fixes: rhbz#1990615
- Fixes: rhbz#1992573
* Fri Jul 23 2021 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.0-3
- Rebuilt for [link moved to references]

```");

  script_tag(name:"affected", value:"'python-notebook' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-notebook", rpm:"python-notebook~7.0.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-notebook", rpm:"python3-notebook~7.0.0~1.fc39", rls:"FC39"))) {
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
