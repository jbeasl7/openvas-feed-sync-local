# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130111");
  script_cve_id("CVE-2015-3238");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:51 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-08-25 15:08:09 +0000 (Tue, 25 Aug 2015)");

  script_name("Mageia: Security Advisory (MGASA-2015-0266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0266");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0266.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16212");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-June/161249.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the MGASA-2015-0266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"If SELinux is enabled, the _unix_run_helper_binary function in Linux-PAM
1.1.8 and earlier hangs indefinitely when verifying a password of 65536
characters, which allows attackers to conduct username enumeration and
denial of service attacks (CVE-2015-3238).");

  script_tag(name:"affected", value:"'pam' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pam-devel", rpm:"lib64pam-devel~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pam0", rpm:"lib64pam0~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam-devel", rpm:"libpam-devel~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam0", rpm:"libpam0~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.1.8~7.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pam-devel", rpm:"lib64pam-devel~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pam0", rpm:"lib64pam0~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam-devel", rpm:"libpam-devel~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpam0", rpm:"libpam0~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.1.8~10.1.mga5", rls:"MAGEIA5"))) {
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
