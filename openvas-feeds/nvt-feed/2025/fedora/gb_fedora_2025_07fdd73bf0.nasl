# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.0710210010073981020");
  script_cve_id("CVE-2025-51591");
  script_tag(name:"creation_date", value:"2025-08-15 04:11:45 +0000 (Fri, 15 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-07fdd73bf0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-07fdd73bf0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-07fdd73bf0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379956");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pandoc' package(s) announced via the FEDORA-2025-07fdd73bf0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update MANUAL to cover threat related to user HTML iframe");

  script_tag(name:"affected", value:"'pandoc' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc", rpm:"ghc-citeproc~0.8.1.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-devel", rpm:"ghc-citeproc-devel~0.8.1.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-doc", rpm:"ghc-citeproc-doc~0.8.1.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-citeproc-prof", rpm:"ghc-citeproc-prof~0.8.1.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark", rpm:"ghc-commonmark~0.2.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-devel", rpm:"ghc-commonmark-devel~0.2.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-doc", rpm:"ghc-commonmark-doc~0.2.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions", rpm:"ghc-commonmark-extensions~0.2.5.5~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-devel", rpm:"ghc-commonmark-extensions-devel~0.2.5.5~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-doc", rpm:"ghc-commonmark-extensions-doc~0.2.5.5~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-extensions-prof", rpm:"ghc-commonmark-extensions-prof~0.2.5.5~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc", rpm:"ghc-commonmark-pandoc~0.2.2.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-devel", rpm:"ghc-commonmark-pandoc-devel~0.2.2.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-doc", rpm:"ghc-commonmark-pandoc-doc~0.2.2.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-pandoc-prof", rpm:"ghc-commonmark-pandoc-prof~0.2.2.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-commonmark-prof", rpm:"ghc-commonmark-prof~0.2.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits", rpm:"ghc-digits~0.3.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-devel", rpm:"ghc-digits-devel~0.3.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-doc", rpm:"ghc-digits-doc~0.3.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-digits-prof", rpm:"ghc-digits-prof~0.3.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables", rpm:"ghc-gridtables~0.1.0.0~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-devel", rpm:"ghc-gridtables-devel~0.1.0.0~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-doc", rpm:"ghc-gridtables-doc~0.1.0.0~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-gridtables-prof", rpm:"ghc-gridtables-prof~0.1.0.0~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb", rpm:"ghc-ipynb~0.2~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-devel", rpm:"ghc-ipynb-devel~0.2~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-doc", rpm:"ghc-ipynb-doc~0.2~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ipynb-prof", rpm:"ghc-ipynb-prof~0.2~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup", rpm:"ghc-jira-wiki-markup~1.5.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-devel", rpm:"ghc-jira-wiki-markup-devel~1.5.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-doc", rpm:"ghc-jira-wiki-markup-doc~1.5.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-jira-wiki-markup-prof", rpm:"ghc-jira-wiki-markup-prof~1.5.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers", rpm:"ghc-ordered-containers~0.2.4~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-devel", rpm:"ghc-ordered-containers-devel~0.2.4~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-doc", rpm:"ghc-ordered-containers-doc~0.2.4~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-ordered-containers-prof", rpm:"ghc-ordered-containers-prof~0.2.4~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc", rpm:"ghc-pandoc~3.1.11.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-devel", rpm:"ghc-pandoc-devel~3.1.11.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-doc", rpm:"ghc-pandoc-doc~3.1.11.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-pandoc-prof", rpm:"ghc-pandoc-prof~3.1.11.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst", rpm:"ghc-typst~0.5.0.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-devel", rpm:"ghc-typst-devel~0.5.0.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-doc", rpm:"ghc-typst-doc~0.5.0.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-typst-prof", rpm:"ghc-typst-prof~0.5.0.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation", rpm:"ghc-unicode-collation~0.1.3.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-devel", rpm:"ghc-unicode-collation-devel~0.1.3.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-doc", rpm:"ghc-unicode-collation-doc~0.1.3.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghc-unicode-collation-prof", rpm:"ghc-unicode-collation-prof~0.1.3.6~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc", rpm:"pandoc~3.1.11.1~33.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pandoc-common", rpm:"pandoc-common~3.1.11.1~33.fc42", rls:"FC42"))) {
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
