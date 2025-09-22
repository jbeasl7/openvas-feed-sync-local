# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886393");
  script_cve_id("CVE-2023-35936", "CVE-2023-38745");
  script_tag(name:"creation_date", value:"2024-04-03 01:16:01 +0000 (Wed, 03 Apr 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 13:43:26 +0000 (Thu, 03 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-b458482d48)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b458482d48");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b458482d48");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2068718");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163472");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220871");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220873");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225379");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227034");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266093");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghc-base64, ghc-hakyll, ghc-isocline, ghc-toml-parser, gitit, pandoc, pandoc-cli, patat' package(s) announced via the FEDORA-2024-b458482d48 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2023-35936 and CVE-2023-38745

pandoc:

- backport fixes for CVE-2023-35936 and CVE-2023-38745

pandoc-cli:

 - new package for pandoc binary

patat:

- update to 0.11.0.0 and enable tests

base64, isocline, toml-parser: now packaged in Fedora");

  script_tag(name:"affected", value:"'ghc-base64, ghc-hakyll, ghc-isocline, ghc-toml-parser, gitit, pandoc, pandoc-cli, patat' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghc-base64", rpm:"ghc-base64~0.4.2.4~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-base64-devel", rpm:"ghc-base64-devel~0.4.2.4~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-base64-doc", rpm:"ghc-base64-doc~0.4.2.4~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-base64-prof", rpm:"ghc-base64-prof~0.4.2.4~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc", rpm:"ghc-citeproc~0.8.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-devel", rpm:"ghc-citeproc-devel~0.8.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-doc", rpm:"ghc-citeproc-doc~0.8.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-prof", rpm:"ghc-citeproc-prof~0.8.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark", rpm:"ghc-commonmark~0.2.4.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-devel", rpm:"ghc-commonmark-devel~0.2.4.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-doc", rpm:"ghc-commonmark-doc~0.2.4.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions", rpm:"ghc-commonmark-extensions~0.2.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-devel", rpm:"ghc-commonmark-extensions-devel~0.2.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-doc", rpm:"ghc-commonmark-extensions-doc~0.2.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-prof", rpm:"ghc-commonmark-extensions-prof~0.2.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc", rpm:"ghc-commonmark-pandoc~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-devel", rpm:"ghc-commonmark-pandoc-devel~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-doc", rpm:"ghc-commonmark-pandoc-doc~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-prof", rpm:"ghc-commonmark-pandoc-prof~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-prof", rpm:"ghc-commonmark-prof~0.2.4.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits", rpm:"ghc-digits~0.3.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-devel", rpm:"ghc-digits-devel~0.3.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-doc", rpm:"ghc-digits-doc~0.3.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-prof", rpm:"ghc-digits-prof~0.3.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gitit", rpm:"ghc-gitit~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gitit-devel", rpm:"ghc-gitit-devel~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gitit-doc", rpm:"ghc-gitit-doc~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gitit-prof", rpm:"ghc-gitit-prof~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables", rpm:"ghc-gridtables~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-devel", rpm:"ghc-gridtables-devel~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-doc", rpm:"ghc-gridtables-doc~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-prof", rpm:"ghc-gridtables-prof~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hakyll", rpm:"ghc-hakyll~4.16.2.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hakyll-devel", rpm:"ghc-hakyll-devel~4.16.2.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hakyll-doc", rpm:"ghc-hakyll-doc~4.16.2.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hakyll-prof", rpm:"ghc-hakyll-prof~4.16.2.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli", rpm:"ghc-hslua-cli~1.4.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-devel", rpm:"ghc-hslua-cli-devel~1.4.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-doc", rpm:"ghc-hslua-cli-doc~1.4.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-cli-prof", rpm:"ghc-hslua-cli-prof~1.4.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list", rpm:"ghc-hslua-list~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-devel", rpm:"ghc-hslua-list-devel~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-doc", rpm:"ghc-hslua-list-doc~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-list-prof", rpm:"ghc-hslua-list-prof~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout", rpm:"ghc-hslua-module-doclayout~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-devel", rpm:"ghc-hslua-module-doclayout-devel~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-doc", rpm:"ghc-hslua-module-doclayout-doc~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-doclayout-prof", rpm:"ghc-hslua-module-doclayout-prof~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path", rpm:"ghc-hslua-module-path~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-devel", rpm:"ghc-hslua-module-path-devel~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-doc", rpm:"ghc-hslua-module-path-doc~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-path-prof", rpm:"ghc-hslua-module-path-prof~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system", rpm:"ghc-hslua-module-system~1.1.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-devel", rpm:"ghc-hslua-module-system-devel~1.1.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-doc", rpm:"ghc-hslua-module-system-doc~1.1.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-system-prof", rpm:"ghc-hslua-module-system-prof~1.1.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version", rpm:"ghc-hslua-module-version~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-devel", rpm:"ghc-hslua-module-version-devel~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-doc", rpm:"ghc-hslua-module-version-doc~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-version-prof", rpm:"ghc-hslua-module-version-prof~1.1.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip", rpm:"ghc-hslua-module-zip~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-devel", rpm:"ghc-hslua-module-zip-devel~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-doc", rpm:"ghc-hslua-module-zip-doc~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-module-zip-prof", rpm:"ghc-hslua-module-zip-prof~1.1.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl", rpm:"ghc-hslua-repl~0.1.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-devel", rpm:"ghc-hslua-repl-devel~0.1.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-doc", rpm:"ghc-hslua-repl-doc~0.1.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-hslua-repl-prof", rpm:"ghc-hslua-repl-prof~0.1.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb", rpm:"ghc-ipynb~0.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-devel", rpm:"ghc-ipynb-devel~0.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-doc", rpm:"ghc-ipynb-doc~0.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-prof", rpm:"ghc-ipynb-prof~0.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-isocline", rpm:"ghc-isocline~1.0.9~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-isocline-devel", rpm:"ghc-isocline-devel~1.0.9~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-isocline-doc", rpm:"ghc-isocline-doc~1.0.9~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-isocline-prof", rpm:"ghc-isocline-prof~1.0.9~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup", rpm:"ghc-jira-wiki-markup~1.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-devel", rpm:"ghc-jira-wiki-markup-devel~1.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-doc", rpm:"ghc-jira-wiki-markup-doc~1.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-prof", rpm:"ghc-jira-wiki-markup-prof~1.5.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg", rpm:"ghc-lpeg~1.0.4~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-devel", rpm:"ghc-lpeg-devel~1.0.4~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-doc", rpm:"ghc-lpeg-doc~1.0.4~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-lpeg-prof", rpm:"ghc-lpeg-prof~1.0.4~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers", rpm:"ghc-ordered-containers~0.2.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-devel", rpm:"ghc-ordered-containers-devel~0.2.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-doc", rpm:"ghc-ordered-containers-doc~0.2.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-prof", rpm:"ghc-ordered-containers-prof~0.2.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc", rpm:"ghc-pandoc~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-devel", rpm:"ghc-pandoc-devel~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-doc", rpm:"ghc-pandoc-doc~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine", rpm:"ghc-pandoc-lua-engine~0.2.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-devel", rpm:"ghc-pandoc-lua-engine-devel~0.2.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-doc", rpm:"ghc-pandoc-lua-engine-doc~0.2.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-engine-prof", rpm:"ghc-pandoc-lua-engine-prof~0.2.0.1~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal", rpm:"ghc-pandoc-lua-marshal~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-devel", rpm:"ghc-pandoc-lua-marshal-devel~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-doc", rpm:"ghc-pandoc-lua-marshal-doc~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-lua-marshal-prof", rpm:"ghc-pandoc-lua-marshal-prof~0.2.2~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-prof", rpm:"ghc-pandoc-prof~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-patat", rpm:"ghc-patat~0.11.0.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-patat-devel", rpm:"ghc-patat-devel~0.11.0.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-patat-doc", rpm:"ghc-patat-doc~0.11.0.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-patat-prof", rpm:"ghc-patat-prof~0.11.0.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-toml-parser", rpm:"ghc-toml-parser~1.3.2.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-toml-parser-devel", rpm:"ghc-toml-parser-devel~1.3.2.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-toml-parser-doc", rpm:"ghc-toml-parser-doc~1.3.2.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-toml-parser-prof", rpm:"ghc-toml-parser-prof~1.3.2.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst", rpm:"ghc-typst~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-devel", rpm:"ghc-typst-devel~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-doc", rpm:"ghc-typst-doc~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-prof", rpm:"ghc-typst-prof~0.1.0.0~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation", rpm:"ghc-unicode-collation~0.1.3.5~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-devel", rpm:"ghc-unicode-collation-devel~0.1.3.5~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-doc", rpm:"ghc-unicode-collation-doc~0.1.3.5~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-prof", rpm:"ghc-unicode-collation-prof~0.1.3.5~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitit", rpm:"gitit~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitit-common", rpm:"gitit-common~0.15.1.1~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc", rpm:"pandoc~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-cli", rpm:"pandoc-cli~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-common", rpm:"pandoc-common~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-pdf", rpm:"pandoc-pdf~3.1.3~29.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"patat", rpm:"patat~0.11.0.0~1.fc39", rls:"FC39"))) {
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
