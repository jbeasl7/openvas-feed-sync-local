# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0397");
  script_cve_id("CVE-2024-53920");
  script_tag(name:"creation_date", value:"2024-12-25 04:11:08 +0000 (Wed, 25 Dec 2024)");
  script_version("2024-12-25T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-12-25 05:05:36 +0000 (Wed, 25 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0397)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0397");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0397.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33867");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/P4KYDPPUCZHJVNAEXLQAF43YKVZPVWFH/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs' package(s) announced via the MGASA-2024-0397 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In elisp-mode.el in GNU Emacs through 30.0.92, a user who chooses to
invoke elisp-completion-at-point (for code completion) on untrusted
Emacs Lisp source code can trigger unsafe Lisp macro expansion that
allows attackers to execute arbitrary code. (This unsafe expansion also
occurs if a user chooses to enable on-the-fly diagnosis that byte
compiles untrusted Emacs Lisp source code). (CVE-2024-53920)");

  script_tag(name:"affected", value:"'emacs' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"emacs", rpm:"emacs~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common", rpm:"emacs-common~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-doc", rpm:"emacs-doc~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-el", rpm:"emacs-el~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-leim", rpm:"emacs-leim~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nox", rpm:"emacs-nox~29.4~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-pgtk", rpm:"emacs-pgtk~29.4~1.2.mga9", rls:"MAGEIA9"))) {
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
