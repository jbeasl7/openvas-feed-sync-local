# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122151");
  script_cve_id("CVE-2010-3858", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1770", "CVE-2011-1771");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:13:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0836)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0836");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0836.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0836 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.2.1.el6]
- [kernel] lib/vsprintf.c: add %pU to print UUID/GUIDs (Frantisek Hrbata) [704280 700299]
- [scsi] megaraid_sas: Driver only report tape drive, JBOD and logic drives (Tomas Henzl) [704601 619422]

[2.6.32-131.1.1.el6]
- [net] dccp: handle invalid feature options length (Jiri Pirko) [703012 703013] {CVE-2011-1770}
- [fs] cifs: check for private_data before trying to put it (Jeff Layton) [703017 702642] {CVE-2011-1771}
- [net] can: add missing socket check in can/raw and can/bcm release (Jiri Pirko) [698482 698483] {CVE-2011-1748 CVE-2011-1598}
- [netdrv] ixgbe: do not clear FCoE DDP error status for received ABTS (Andy Gospodarek) [704011 695966]
- [netdrv] ixgbe: DCB remove ixgbe_fcoe_getapp routine (Andy Gospodarek) [704002 694358]
- [fs] setup_arg_pages: diagnose excessive argument size (Oleg Nesterov) [645228 645229] {CVE-2010-3858}
- [scsi] bfa: change tech-preview to cover all cases (Rob Evers) [704014 703251]
- [scsi] bfa: driver version update (Rob Evers) [704282 703265]
- [scsi] bfa: kdump fix (Rob Evers) [704282 703265]
- [scsi] bfa: firmware download fix (Rob Evers) [704282 703265]
- [netdrv] bna: fix memory leak during RX path cleanup (Ivan Vecera) [704000 698625]
- [netdrv] bna: fix for clean fw re-initialization (Ivan Vecera) [704000 698625]
- [scsi] ipr: improve interrupt service routine performance (Steve Best) [704009 696754]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.2.1.el6", rls:"OracleLinux6"))) {
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
