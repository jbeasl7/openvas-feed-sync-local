# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130115");
  script_cve_id("CVE-2015-3218", "CVE-2015-3255", "CVE-2015-3256", "CVE-2015-4625");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:53 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0262.html");
  script_xref(name:"URL", value:"http://lists.freedesktop.org/archives/polkit-devel/2015-July/000432.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16135");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit' package(s) announced via the MGASA-2015-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Local privilege escalation in polkit before 0.113 due to predictable
authentication session cookie values (CVE-2015-4625).

Various memory corruption vulnerabilities in polkit before 0.113 in the
use of the JavaScript interpreter, possibly leading to local privilege
escalation (CVE-2015-3256).

Memory corruption vulnerability in polkit before 0.113 in handling
duplicate action IDs, possibly leading to local privilege escalation
(CVE-2015-3255).

Denial of service issue in polkit before 0.113 which allowed any local
user to crash polkitd (CVE-2015-3218).");

  script_tag(name:"affected", value:"'polkit' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit-gir1.0", rpm:"lib64polkit-gir1.0~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1-devel", rpm:"lib64polkit1-devel~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1_0", rpm:"lib64polkit1_0~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gir1.0", rpm:"libpolkit-gir1.0~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1-devel", rpm:"libpolkit1-devel~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1_0", rpm:"libpolkit1_0~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.113~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-desktop-policy", rpm:"polkit-desktop-policy~0.113~1.mga4", rls:"MAGEIA4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit-gir1.0", rpm:"lib64polkit-gir1.0~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1-devel", rpm:"lib64polkit1-devel~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polkit1_0", rpm:"lib64polkit1_0~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gir1.0", rpm:"libpolkit-gir1.0~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1-devel", rpm:"libpolkit1-devel~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit1_0", rpm:"libpolkit1_0~0.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~0.113~1.mga5", rls:"MAGEIA5"))) {
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
