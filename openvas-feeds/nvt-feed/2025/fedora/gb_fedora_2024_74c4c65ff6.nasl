# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.7499499651021026");
  script_cve_id("CVE-2022-1996", "CVE-2022-24675", "CVE-2022-27191", "CVE-2022-28327", "CVE-2022-29526", "CVE-2022-30629", "CVE-2022-41723");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-16 12:54:30 +0000 (Thu, 16 Jun 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2024-74c4c65ff6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-74c4c65ff6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-74c4c65ff6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2119456");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2120895");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2130931");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2136314");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2140412");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2160637");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2172749");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178465");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2183053");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2190065");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2198979");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2208103");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2211674");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218220");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218708");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221432");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222161");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274184");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild");
  script_xref(name:"URL", value:"https://pagure.io/releng/issue/12057");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-guest-agent' package(s) announced via the FEDORA-2024-74c4c65ff6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for google-guest-agent-20240314.00-4.fc41.

##### **Changelog**

```
* Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-4
- Skip events test
* Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-3
- Fix typo in License filename
* Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-2
- Sync packit config with other GCP pkgs
* Wed Apr 10 2024 Major Hayden <major@redhat.com> - 20240314.00-1
- Update to 20240314.00 rhbz#2274184
* Wed Apr 10 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-8
- Unretirement Releng Request: [link moved to references]
* Sun Feb 11 2024 Maxwell G <maxwell@gtmx.me> - 20230726.00-7
- Rebuild for golang 1.22.0
* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-6
- Rebuilt for [link moved to references]
* Sat Jan 20 2024 Fedora Release Engineering <releng@fedoraproject.org> - 20230726.00-5
- Rebuilt for [link moved to references]
* Wed Sep 6 2023 Major Hayden <major@redhat.com> - 20230726.00-4
- PRs to rawhide only
* Fri Jul 28 2023 Major Hayden <major@redhat.com> - 20230726.00-3
- Fix typo on ppc64le
* Fri Jul 28 2023 Major Hayden <major@redhat.com> - 20230726.00-2
- Disable ppc64/s390x arches
* Fri Jul 28 2023 Packit <hello@packit.dev> - 20230726.00-1
- [packit] 20230726.00 upstream release
* Tue Jul 25 2023 Major Hayden <major@redhat.com> - 20230725.00-2
- Disable koji auto build with packit
* Tue Jul 25 2023 Packit <hello@packit.dev> - 20230725.00-1
- [packit] 20230725.00 upstream release
* Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 20230711.00-2
- Rebuilt for [link moved to references]
* Wed Jul 12 2023 Major Hayden <major@redhat.com> - 20230711.00-1
- Update to 20230711.00 rhbz#2222161
* Wed Jul 12 2023 Major Hayden <major@redhat.com> - 20230707.00-2
- Add packit config
* Tue Jul 11 2023 Major Hayden <major@redhat.com> - 20230707.00-1
- Update to 20230707.00 rhbz#2221432
* Mon Jul 3 2023 Major Hayden <major@redhat.com> - 20230628.00-1
- Update to 20230628.00 rhbz#2218708
* Wed Jun 28 2023 Major Hayden <major@redhat.com> - 20230626.00-1
- Update to 20230626.00 rhbz#2218220
* Mon Jun 12 2023 Major Hayden <major@redhat.com> - 20230601.00-1
- Update to 20230601.00 rhbz#2211674
* Thu May 18 2023 Major Hayden <major@redhat.com> - 20230517.00-1
- Update to 20230517.00 rhbz#2208103
* Mon May 15 2023 Major Hayden <major@redhat.com> - 20230510.00-1
- Update to 20230510.00 rhbz#2198979
* Mon May 1 2023 Major Hayden <major@redhat.com> - 20230426.00-1
- Update to 20230426.00 rhbz#2190065
* Thu Apr 6 2023 Major Hayden <major@redhat.com> - 20230403.00-1
- Update to 20230403.00 rhbz#2183053
* Tue Mar 28 2023 Major Hayden <major@redhat.com> - 20230221.00-2
- Bump revision for rebuild rhbz#2178465
* Tue Feb 28 2023 Major Hayden <major@redhat.com> - 20230221.00-1
- Update to 20230221.00 rhbz#2172749
* Wed Feb 22 2023 Major ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'google-guest-agent' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"google-guest-agent", rpm:"google-guest-agent~20240314.00~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-guest-agent-debuginfo", rpm:"google-guest-agent-debuginfo~20240314.00~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-guest-agent-debugsource", rpm:"google-guest-agent-debugsource~20240314.00~4.fc41", rls:"FC41"))) {
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
