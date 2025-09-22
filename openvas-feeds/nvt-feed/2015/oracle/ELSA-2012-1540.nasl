# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123774");
  script_cve_id("CVE-2012-2372", "CVE-2012-3552", "CVE-2012-4508", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-5513");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:33:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-1540)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1540");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1540.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.24.1.el5, oracleasm-2.6.18-308.24.1.el5' package(s) announced via the ELSA-2012-1540 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-308.24.1.el5]
- Revert: [scsi] sg: fix races during device removal (Ewan Milne) [868950 861004]

[2.6.18-308.23.1.el5]
- [net] bnx2x: Add remote-fault link detection (Alexander Gordeev) [870120 796905]
- [net] bnx2x: Cosmetic changes (Alexander Gordeev) [870120 796905]
- [net] rds-ping cause kernel panic (Alexander Gordeev) [822755 822756] {CVE-2012-2372}
- [xen] add guest address range checks to XENMEM_exchange handlers (Igor Mammedov) [878033 878034] {CVE-2012-5513}
- [xen] x86/physmap: Prevent incorrect updates of m2p mappings (Igor Mammedov) [870148 870149] {CVE-2012-4537}
- [xen] VCPU/timer: Dos vulnerability prev overflow in calculations (Igor Mammedov) [870150 870151] {CVE-2012-4535}
- [scsi] sg: fix races during device removal (Ewan Milne) [868950 861004]

[2.6.18-308.22.1.el5]
- [net] bonding: fix link down handling in 802.3ad mode (Andy Gospodarek) [877943 782866]

[2.6.18-308.21.1.el5]
- [fs] ext4: race-cond protect for convert_unwritten_extents_endio (Lukas Czerner) [869910 869911] {CVE-2012-4508}
- [fs] ext4: serialize fallocate w/ ext4_convert_unwritten_extents (Lukas Czerner) [869910 869911] {CVE-2012-4508}
- [fs] ext4: flush the i_completed_io_list during ext4_truncate (Lukas Czerner) [869910 869911] {CVE-2012-4508}
- [net] WARN if struct ip_options was allocated directly by kmalloc (Jiri Pirko) [874973 872612]
- [net] ipv4: add RCU protection to inet->opt (Jiri Pirko) [872113 855302] {CVE-2012-3552}
- [scsi] qla2xx: Don't toggle inter bits after IRQ lines attached (Chad Dupuis) [870118 800708]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.24.1.el5, oracleasm-2.6.18-308.24.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.24.1.el5", rpm:"ocfs2-2.6.18-308.24.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.24.1.el5PAE", rpm:"ocfs2-2.6.18-308.24.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.24.1.el5debug", rpm:"ocfs2-2.6.18-308.24.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.24.1.el5xen", rpm:"ocfs2-2.6.18-308.24.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.24.1.el5", rpm:"oracleasm-2.6.18-308.24.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.24.1.el5PAE", rpm:"oracleasm-2.6.18-308.24.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.24.1.el5debug", rpm:"oracleasm-2.6.18-308.24.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.24.1.el5xen", rpm:"oracleasm-2.6.18-308.24.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
