# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0297");
  script_cve_id("CVE-2020-24330", "CVE-2020-24331", "CVE-2020-24332");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-19 21:03:04 +0000 (Wed, 19 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0297)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0297");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0297.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26658");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SSDL7COIFCZQMUBNAASNMKMX7W5JUHRD/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/08/14/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trousers' package(s) announced via the MGASA-2021-0297 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in TrouSerS through 0.3.14. If the tcsd daemon is
started with root privileges instead of by the tss user, it fails to drop the
root gid privilege when no longer needed (CVE-2020-24330).

An issue was discovered in TrouSerS through 0.3.14. If the tcsd daemon is started
with root privileges, the tss user still has read and write access to the
/etc/tcsd.conf file (which contains various settings related to this daemon)
(CVE-2020-24331).

An issue was discovered in TrouSerS through 0.3.14. If the tcsd daemon is
started with root privileges, the creation of the system.data file is prone to
symlink attacks. The tss user can be used to create or corrupt existing files,
which could possibly lead to a DoS attack (CVE-2020-24332).");

  script_tag(name:"affected", value:"'trousers' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64trousers-devel", rpm:"lib64trousers-devel~0.3.14~4.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tspi1", rpm:"lib64tspi1~0.3.14~4.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtrousers-devel", rpm:"libtrousers-devel~0.3.14~4.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtspi1", rpm:"libtspi1~0.3.14~4.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trousers", rpm:"trousers~0.3.14~4.2.mga7", rls:"MAGEIA7"))) {
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
