# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0075");
  script_cve_id("CVE-2025-1244");
  script_tag(name:"creation_date", value:"2025-02-26 04:08:53 +0000 (Wed, 26 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 15:15:18 +0000 (Wed, 12 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0075");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0075.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34045");
  script_xref(name:"URL", value:"https://git.savannah.gnu.org/cgit/emacs.git/commit/?id=820f0793f0b46448928905552726c1f1b999062f");
  script_xref(name:"URL", value:"https://lwn.net/Articles/1011611/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs' package(s) announced via the MGASA-2025-0075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A command injection flaw was found which could allow a remote,
unauthenticated attacker to execute arbitrary shell commands by tricking
users into visiting a specially crafted website or an HTTP URL with a
redirect.");

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

  if(!isnull(res = isrpmvuln(pkg:"emacs", rpm:"emacs~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common", rpm:"emacs-common~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-doc", rpm:"emacs-doc~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-el", rpm:"emacs-el~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-leim", rpm:"emacs-leim~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nox", rpm:"emacs-nox~29.4~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-pgtk", rpm:"emacs-pgtk~29.4~1.3.mga9", rls:"MAGEIA9"))) {
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
