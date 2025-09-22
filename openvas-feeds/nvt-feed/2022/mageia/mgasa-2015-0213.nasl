# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0213");
  script_cve_id("CVE-2013-7041", "CVE-2014-2583");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0213");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0213.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11937");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146370.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the MGASA-2015-0213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated pam packages fix security vulnerabilities:

The pam_userdb module for Pam uses a case-insensitive method to compare hashed
passwords, which makes it easier for attackers to guess the password via a
brute force attack (CVE-2013-7041).

Multiple directory traversal vulnerabilities in pam_timestamp.c in the
pam_timestamp module for Linux-PAM (aka pam) 1.1.8 allow local users to create
aribitrary files or possibly bypass authentication via a .. (dot dot) in the
PAM_RUSER value to the get_ruser function or (2) PAM_TTY value to the
check_tty function, which is used by the format_timestamp_name function
(CVE-2014-2583).");

  script_tag(name:"affected", value:"'pam' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pam-devel", rpm:"lib64pam-devel~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pam0", rpm:"lib64pam0~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam-devel", rpm:"libpam-devel~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam0", rpm:"libpam0~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.1.8~7.1.mga4", rls:"MAGEIA4"))) {
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
