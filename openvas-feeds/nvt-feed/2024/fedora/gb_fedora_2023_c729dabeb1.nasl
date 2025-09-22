# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.997291009798101981");
  script_cve_id("CVE-2015-20107", "CVE-2021-28861", "CVE-2023-24329");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:33 +0000 (Wed, 09 Nov 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-c729dabeb1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c729dabeb1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-c729dabeb1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992600");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2003682");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2053880");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2059670");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2069873");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2075390");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2120789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2147520");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2174020");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2203423");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Changes/LIBFFI34");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy3.10' package(s) announced via the FEDORA-2023-c729dabeb1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for pypy3.10-7.3.12-1.3.10.fc40.

##### **Changelog**

```
* Wed Jul 26 2023 Miro Hroncok <mhroncok@redhat.com> - 7.3.12-1.3.10
- Initial PyPy 3.10 package
* Wed Jul 26 2023 Miro Hroncok <mhroncok@redhat.com> - 7.3.12-1.3.9
- Update to 7.3.12
- Fixes: rhbz#2203423
* Fri Jul 21 2023 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.11-5.3.9
- Rebuilt for [link moved to references]
* Mon May 29 2023 Charalampos Stratakis <cstratak@redhat.com> - 7.3.11-4.3.9
- Security fix for CVE-2023-24329
Resolves: rhbz#2174020
* Fri Feb 17 2023 Miro Hroncok <mhroncok@redhat.com> - 7.3.11-3.3.9
- On Fedora 38+, obsolete the pypy3.8 package which is no longer available
* Fri Jan 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.11-2.3.9
- Rebuilt for [link moved to references]
* Fri Dec 30 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.11-1.3.9
- Update to 7.3.11
- Fixes: rhbz#2147520
* Fri Dec 2 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.9-5.3.9
- On Fedora 37+, obsolete the pypy3.7 package which is no longer available
* Mon Oct 10 2022 Lumir Balhar <lbalhar@redhat.com> - 7.3.9-4.3.9
- Backport fix for CVE-2021-28861
Resolves: rhbz#2120789
* Fri Jul 22 2022 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.9-3.3.9
- Rebuilt for [link moved to references]
* Tue Jun 28 2022 Charalampos Stratakis <cstratak@redhat.com> - 7.3.9-2.3.9
- Security fix for CVE-2015-20107
- Fixes: rhbz#2075390
* Wed Mar 30 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.9-1.3.9
- Update to 7.3.9
- Fixes: rhbz#2069873
* Tue Mar 1 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.8-1.3.9
- Include the Python version in Release to workaround debuginfo conflicts
 and make same builds of different PyPy sort in a predictable way (e.g. wrt Obsoletes)
- Namespace the debugsources to fix installation conflict with other PyPys
- Fixes: rhbz#2053880
- This is now the main PyPy 3 on Fedora 36+
- Fixes: rhbz#2059670
* Tue Feb 22 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.8-1
- Update to 7.3.8 final
* Fri Feb 11 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.8~rc2-1
- Update to 7.3.8rc2
* Wed Jan 26 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.8~rc1-1
- Update to 7.3.8rc1
- Move to a CPython-like installation layout
- Stop requiring pypy3.9 from pypy3.9-libs
- Split tests into pypy3.9-test
* Fri Jan 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 7.3.7-3
- Rebuilt for [link moved to references]
* Sat Jan 8 2022 Miro Hroncok <mhroncok@redhat.com> - 7.3.7-2
- Rebuilt for [link moved to references]
* Thu Nov 11 2021 Miro Hroncok <mhroncok@redhat.com> - 7.3.7-1
- Initial pypy3.8 package
- Supplement tox
* Tue Oct 26 2021 Tomas Hrnciar <thrnciar@redhat.com> - 7.3.6-1
- Update to 7.3.6
- Remove windows executable binaries
- Fixes: rhbz#2003682
* Mon Sep 20 2021 Miro Hroncok <mhroncok@redhat.com> - 7.3.5-2
- Explicitly buildrequire OpenSSL 1.1, as Python 3.7 is not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pypy3.10' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10", rpm:"pypy3.10~7.3.12~1.3.10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10-debugsource", rpm:"pypy3.10-debugsource~7.3.12~1.3.10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10-devel", rpm:"pypy3.10-devel~7.3.12~1.3.10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10-libs", rpm:"pypy3.10-libs~7.3.12~1.3.10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10-libs-debuginfo", rpm:"pypy3.10-libs-debuginfo~7.3.12~1.3.10.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy3.10-test", rpm:"pypy3.10-test~7.3.12~1.3.10.fc40", rls:"FC40"))) {
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
