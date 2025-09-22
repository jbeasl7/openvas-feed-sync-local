# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122928");
  script_cve_id("CVE-2015-8767");
  script_tag(name:"creation_date", value:"2016-05-09 11:24:45 +0000 (Mon, 09 May 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 16:53:00 +0000 (Thu, 30 Aug 2018)");

  script_name("Oracle: Security Advisory (ELSA-2016-3551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-3551");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-3551.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-118.6.1.el6uek, dtrace-modules-3.8.13-118.6.1.el7uek, kernel-uek' package(s) announced via the ELSA-2016-3551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-118.6.1]
- skbuff: skb_segment: orphan frags before copying (Dongli Zhang) [Orabug: 23018911]
- RDS/IB: VRPC DELAY / OSS RECONNECT CAUSES 5 MINUTE STALL ON PORT FAILURE (Venkat Venkatsubra) [Orabug: 22888920]
- mlx4_core: Introduce restrictions for PD update (Ajaykumar Hotchandani)
- filename should be destroyed via final_putname() instead of __putname() (John Sobecki) [Orabug: 22346320]
- RDS: Fix the atomicity for congestion map update (Wengang Wang) [Orabug: 23141554]
- sctp: Prevent soft lockup when sctp_accept() is called during a timeout event (Karl Heiss) [Orabug: 23222753] {CVE-2015-8767}

[3.8.13-118.5.1]
- x86_64: expand kernel stack to 16K (Minchan Kim) [Orabug: 21140371]
- iommu/vt-d: add quirk for broken interrupt remapping on 55XX chipsets (Neil Horman) [Orabug: 22534160]
- xen: remove unneeded variables and one constant (Daniel Kiper) [Orabug: 22288700]
- Revert 'x86/xen: delay construction of mfn_list_list' (Daniel Kiper) [Orabug: 22288700]
- ocfs2/dlm: fix misuse of list_move_tail() in dlm_run_purge_list() (Tariq Saeed) [Orabug: 22898384]
- ocfs2/dlm: do not purge lockres that is queued for assert master (Xue jiufei) [Orabug: 22898384]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-118.6.1.el6uek, dtrace-modules-3.8.13-118.6.1.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.6.1.el6uek", rpm:"dtrace-modules-3.8.13-118.6.1.el6uek~0.4.5~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.6.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.6.1.el7uek", rpm:"dtrace-modules-3.8.13-118.6.1.el7uek~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.6.1.el7uek", rls:"OracleLinux7"))) {
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
