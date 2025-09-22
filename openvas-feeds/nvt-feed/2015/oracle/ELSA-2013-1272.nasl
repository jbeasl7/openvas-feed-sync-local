# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123571");
  script_cve_id("CVE-2013-4296", "CVE-2013-4311");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:40 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1272");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1272.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the ELSA-2013-1272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.10.2-18.0.1.el6_4.14]
- Replace docs/et.png in tarball with blank image

[0.10.2-18.el6_4.14]
- spec: Update requirements to pick up rebuilt polkit (CVE-2013-4311)

[0.10.2-18.el6_4.13]
- spec: Fix messed up dependency on polkit (CVE-2013-4311)

[0.10.2-18.el6_4.12]
- Introduce APIs for splitting/joining strings (rhbz#1006265)
- Rename virKillProcess to virProcessKill (rhbz#1006265)
- Rename virPid{Abort, Wait} to virProcess{Abort, Wait} (rhbz#1006265)
- Rename virCommandTranslateStatus to virProcessTranslateStatus (rhbz#1006265)
- Move virProcessKill into virprocess.{h, c} (rhbz#1006265)
- Move virProcess{Kill, Abort, TranslateStatus} into virprocess.{c, h} (rhbz#1006265)
- Include process start time when doing polkit checks (rhbz#1006265)
- Add support for using 3-arg pkcheck syntax for process (CVE-2013-4311)

[0.10.2-18.el6_4.11]
- Fix crash in remoteDispatchDomainMemoryStats (CVE-2013-4296)

[0.10.2-18.el6_4.10]
- qemu: Avoid leaking uri in qemuMigrationPrepareDirect (rhbz#984578)
- qemu: Fix double free in qemuMigrationPrepareDirect (rhbz#984578)
[when parsing a single device (rhbz#1003934)]
- Plug leak in virCgroupMoveTask (rhbz#984556)
- Fix invalid read in virCgroupGetValueStr (rhbz#984561)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.0.1.el6_4.14", rls:"OracleLinux6"))) {
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
