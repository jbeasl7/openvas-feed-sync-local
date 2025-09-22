# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.029984102101305");
  script_cve_id("CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792", "CVE-2021-39191", "CVE-2022-23527");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 20:50:44 +0000 (Fri, 16 Dec 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-02c84fe305)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-02c84fe305");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-02c84fe305");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1900913");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1958466");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966756");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1985153");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986103");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986398");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1993566");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1996926");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2001647");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2082376");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2128328");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2153658");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2164064");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_auth_openidc' package(s) announced via the FEDORA-2023-02c84fe305 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for mod_auth_openidc-2.4.12.3-2.fc39.

##### **Changelog**

```
* Tue Mar 7 2023 Tomas Halman <thalman@redhat.com> - 2.4.12.3-2
migrated to SPDX license
* Tue Feb 28 2023 Tomas Halman <thalman@redhat.com> - 2.4.12.3-1
Rebase to 2.4.12.3 version
- Resolves: rhbz#2164064 - mod_auth_openidc-2.4.12.3 is available
* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.12.2-2
- Rebuilt for [link moved to references]
* Fri Dec 16 2022 Tomas Halman <thalman@redhat.com> - 2.4.12.2-1
Rebase to 2.4.12.2 version
- Resolves: rhbz#2153658 - CVE-2022-23527 mod_auth_openidc: Open Redirect in
 oidc_validate_redirect_url() using tab character
* Thu Sep 22 2022 Tomas Halman <thalman@redhat.com> - 2.4.11.2-3
- Resolves: rhbz#2128328 - Port pcre dependency to pcre2
* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.11.2-2
- Rebuilt for [link moved to references]
* Thu Jun 23 2022 Tomas Halman <thalman@redhat.com> - 2.4.11.2-1
- Resolves: rhbz#2082376 - New version 2.4.11.2 available
* Mon Apr 11 2022 Tomas Halman <thalman@redhat.com> - 2.4.11.1-1
- Resolves: rhbz#1996926 - New version 2.4.11.1 available
* Thu Mar 31 2022 Tomas Halman <thalman@redhat.com> - 2.4.9.4-1
- Resolves: rhbz#2001647 - CVE-2021-39191 mod_auth_openidc: open redirect
 by supplying a crafted URL in the target_link_uri
 parameter
* Thu Jan 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.9.1-3
- Rebuilt for [link moved to references]
* Tue Sep 14 2021 Sahana Prasad <sahana@redhat.com> - 2.4.9.1-2
- Rebuilt with OpenSSL 3.0.0
* Wed Aug 18 2021 Jakub Hrozek <jhrozek@redhat.com> - 2.4.9.1-1
- New upstream release
- Resolves: rhbz#1993566 - mod_auth_openidc-2.4.9.1 is available
* Fri Jul 30 2021 Jakub Hrozek <jhrozek@redhat.com> - 2.4.9-1
- Resolves: rhbz#1985153 - mod_auth_openidc-2.4.9 is available
- Resolves: rhbz#1986103 - CVE-2021-32786 mod_auth_openidc: open redirect
 in oidc_validate_redirect_url()
- Resolves: rhbz#1986396 - CVE-2021-32791 mod_auth_openidc: hardcoded
 static IV and AAD with a reused key in AES GCM
 encryption
- Resolves: rhbz#1986398 - CVE-2021-32792 mod_auth_openidc: XSS when using
 OIDCPreservePost On
* Thu Jul 22 2021 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.8.4-2
- Rebuilt for [link moved to references]
* Wed Jun 2 2021 Jakub Hrozek <jhrozek@redhat.com> - 2.4.8.3-1
- New upstream release
- Resolves: rhbz#1966756 - mod_auth_openidc-2.4.8.3 is available
* Mon May 10 2021 Jakub Hrozek <jhrozek@redhat.com> - 2.4.8.2-1
- New upstream release
- Resolves: rhbz#1958466 - mod_auth_openidc-2.4.8.2 is available
* Thu May 6 2021 Jakub Hrozek <jhrozek@redhat.com> - 2.4.7.2-1
- New upstream release
- Resolves: rhbz#1900913 - mod_auth_openidc-2.4.7.2 is available
* Fri Apr 30 2021 Tomas Halman <thalman@redhat.com> - 2.4.4.1-3
- Remove unnecessary LTO patch

```");

  script_tag(name:"affected", value:"'mod_auth_openidc' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc", rpm:"mod_auth_openidc~2.4.12.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc-debuginfo", rpm:"mod_auth_openidc-debuginfo~2.4.12.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_auth_openidc-debugsource", rpm:"mod_auth_openidc-debugsource~2.4.12.3~2.fc39", rls:"FC39"))) {
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
