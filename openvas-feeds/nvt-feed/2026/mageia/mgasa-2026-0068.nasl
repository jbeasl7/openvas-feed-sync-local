# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0068");
  script_cve_id("CVE-2026-23554");
  script_tag(name:"creation_date", value:"2026-03-26 04:51:57 +0000 (Thu, 26 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0068");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0068.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35222");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/17/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the MGASA-2026-0068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use after free of paging structures in EPT. (CVE-2026-23554)");

  script_tag(name:"affected", value:"'xen' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xen-devel", rpm:"lib64xen-devel~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xen3.0", rpm:"lib64xen3.0~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen-devel", rpm:"libxen-devel~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxen3.0", rpm:"libxen3.0~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen", rpm:"ocaml-xen~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-xen-devel", rpm:"ocaml-xen-devel~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-hypervisor", rpm:"xen-hypervisor~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-licenses", rpm:"xen-licenses~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-runtime", rpm:"xen-runtime~4.17.5~1.git20251028.3.mga9", rls:"MAGEIA9"))) {
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
