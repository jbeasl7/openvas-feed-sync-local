# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122177");
  script_cve_id("CVE-2010-4565", "CVE-2010-4649", "CVE-2011-0006", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1019", "CVE-2011-1044", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1573");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 17:50:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-2015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-2015");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-2015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, ofa-2.6.32-100.28.15.el5' package(s) announced via the ELSA-2011-2015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-100.28.15.el6]
- sctp: fix to calc the INIT/INIT-ACK chunk length correctly is set {CVE-2011-1573}
- dccp: fix oops on Reset after close {CVE-2011-1093}
- bridge: netfilter: fix information leak {CVE-2011-1080}
- Bluetooth: bnep: fix buffer overflow {CVE-2011-1079}
- net: don't allow CAP_NET_ADMIN to load non-netdev kernel modules {CVE-2011-1019}
- ipip: add module alias for tunl0 tunnel device
- gre: add module alias for gre0 tunnel device
- drm/radeon/kms: check AA resolve registers on r300 {CVE-2011-1016}
- drm/radeon: fix regression with AA resolve checking {CVE-2011-1016}
- drm: fix unsigned vs signed comparison issue in modeset ctl ioctl {CVE-2011-1013}
- proc: protect mm start_code/end_code in /proc/pid/stat {CVE-2011-0726}
- ALSA: caiaq - Fix possible string-buffer overflow {CVE-2011-0712}
- xfs: zero proper structure size for geometry calls {CVE-2011-0711}
- xfs: prevent leaking uninitialized stack memory in FSGEOMETRY_V1 {CVE-2011-0711}
- ima: fix add LSM rule bug {CVE-2011-0006}
- IB/uverbs: Handle large number of entries in poll CQ {CVE-2010-4649, CVE-2011-1044}
- CAN: Use inode instead of kernel address for /proc file {CVE-2010-4565}

[2.6.32-100.28.14.el6]
- IB/qib: fix qib compile warning.
- IB/core: Allow device-specific per-port sysfs files.
- dm crypt: add plain64 iv.
- firmware: add firmware for qib.
- Infiniband: Add QLogic PCIe QLE InfiniBand host channel adapters support.");

  script_tag(name:"affected", value:"'kernel-uek, ofa-2.6.32-100.28.15.el5' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~100.28.15.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-100.28.15.el5", rpm:"ofa-2.6.32-100.28.15.el5~1.5.1~4.0.28", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-100.28.15.el5debug", rpm:"ofa-2.6.32-100.28.15.el5debug~1.5.1~4.0.28", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~100.28.15.el6", rls:"OracleLinux6"))) {
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
