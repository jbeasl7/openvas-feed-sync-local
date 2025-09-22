# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.5982729755988");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-5b272a55b8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-5b272a55b8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-5b272a55b8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343305");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347206");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bigloo, emacs, neovim, rizin, tree-sitter' package(s) announced via the FEDORA-2025-5b272a55b8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to tree-sitter 0.25.2 and emacs 30.1.");

  script_tag(name:"affected", value:"'bigloo, emacs, neovim, rizin, tree-sitter' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"bigloo", rpm:"bigloo~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bigloo-debuginfo", rpm:"bigloo-debuginfo~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bigloo-debugsource", rpm:"bigloo-debugsource~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bigloo-doc", rpm:"bigloo-doc~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bigloo-libs", rpm:"bigloo-libs~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bigloo-libs-debuginfo", rpm:"bigloo-libs-debuginfo~4.6a~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs", rpm:"emacs~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common", rpm:"emacs-common~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common-debuginfo", rpm:"emacs-common-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-debuginfo", rpm:"emacs-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-debugsource", rpm:"emacs-debugsource~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-devel", rpm:"emacs-devel~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-gtk+x11", rpm:"emacs-gtk+x11~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-gtk+x11-debuginfo", rpm:"emacs-gtk+x11-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-lucid", rpm:"emacs-lucid~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-lucid-debuginfo", rpm:"emacs-lucid-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nw", rpm:"emacs-nw~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nw-debuginfo", rpm:"emacs-nw-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacsclient", rpm:"emacsclient~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacsclient-debuginfo", rpm:"emacsclient-debuginfo~30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtree-sitter", rpm:"libtree-sitter~0.25.2~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtree-sitter-debuginfo", rpm:"libtree-sitter-debuginfo~0.25.2~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtree-sitter-devel", rpm:"libtree-sitter-devel~0.25.2~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim", rpm:"neovim~0.10.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debuginfo", rpm:"neovim-debuginfo~0.10.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debugsource", rpm:"neovim-debugsource~0.10.4~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin", rpm:"rizin~0.7.4~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-common", rpm:"rizin-common~0.7.4~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-debuginfo", rpm:"rizin-debuginfo~0.7.4~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-debugsource", rpm:"rizin-debugsource~0.7.4~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-devel", rpm:"rizin-devel~0.7.4~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tree-sitter", rpm:"tree-sitter~0.25.2~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tree-sitter-debugsource", rpm:"tree-sitter-debugsource~0.25.2~8.fc42", rls:"FC42"))) {
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
