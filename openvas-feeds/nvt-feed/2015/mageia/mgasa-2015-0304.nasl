# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130075");
  script_cve_id("CVE-2015-1331", "CVE-2015-1334");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:24 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0304");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0304.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2675-1");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16443");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the MGASA-2015-0304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Roman Fiedler discovered that LXC had a directory traversal flaw when
creating lock files. A local attacker could exploit this flaw to create an
arbitrary file as the root user (CVE-2015-1331).

Roman Fiedler discovered that LXC incorrectly trusted the container's proc
filesystem to set up AppArmor profile changes and SELinux domain
transitions. A local attacker could exploit this flaw to run programs
inside the container that are not confined by AppArmor or SELinux
(CVE-2015-1334).");

  script_tag(name:"affected", value:"'lxc' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc-devel", rpm:"lib64lxc-devel~1.0.5~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lxc1", rpm:"lib64lxc1~1.0.5~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc-devel", rpm:"liblxc-devel~1.0.5~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblxc1", rpm:"liblxc1~1.0.5~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~1.0.5~3.1.mga5", rls:"MAGEIA5"))) {
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
