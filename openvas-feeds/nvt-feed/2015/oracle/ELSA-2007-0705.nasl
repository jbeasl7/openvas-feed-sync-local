# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122663");
  script_cve_id("CVE-2007-1217", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3851");
  script_tag(name:"creation_date", value:"2015-10-08 11:50:33 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2007-0705)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0705");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0705.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-8.1.10.0.1.el5, oracleasm-2.6.18-8.1.10.0.1.el5' package(s) announced via the ELSA-2007-0705 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-8.1.10.0.1.el5]
 - Fix bonding primary=ethX (Bert Barbe) [IT 101532] [ORA 5136660]
 - Add entropy module option to e1000/bnx2 (John Sobecki) [ORA 6045759]

 [2.6.18-8.1.10.el5]
 - [mm] Prevent the stack growth into hugetlb reserved regions (Konrad
 Rzeszutek) [253313] {CVE-2007-3739}

 [2.6.18-8.1.9.el5]
 - [misc] cpuset information leak (Prarit Bhargava ) [245773] {CVE-2007-2875}
 - [net] ip_conntrack_sctp: fix remotely triggerable panic (Don Howard )
 [245774] {CVE-2007-2876}
 - [misc] Overflow in CAPI subsystem (Anton Arapov ) [232260] {CVE-2007-1217}
 - [CIFS] fix signing sec= mount options (Jeff Layton ) [253315]
 {CVE-2007-3843}
 - [CIFS] respect umask when unix extensions are enabled (Jeff Layton )
 [253314] {CVE-2007-3740}
 - [misc] i915_dma: fix batch buffer security bit for i965 chipsets
 (Aristeu Rozanski ) [252305] {CVE-2007-3851}
 - [fs] - Move ms-dos compat ioctl to ms-dos dir (Eric Sandeen ) [253317]
 - [fs] - fix VFAT compat ioctls on 64-bit systems (Eric Sandeen )
 [253317] {CVE-2007-2878}");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-8.1.10.0.1.el5, oracleasm-2.6.18-8.1.10.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~8.1.10.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.10.0.1.el5", rpm:"ocfs2-2.6.18-8.1.10.0.1.el5~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.10.0.1.el5PAE", rpm:"ocfs2-2.6.18-8.1.10.0.1.el5PAE~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-8.1.10.0.1.el5xen", rpm:"ocfs2-2.6.18-8.1.10.0.1.el5xen~1.2.6~6.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.10.0.1.el5", rpm:"oracleasm-2.6.18-8.1.10.0.1.el5~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.10.0.1.el5PAE", rpm:"oracleasm-2.6.18-8.1.10.0.1.el5PAE~2.0.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-8.1.10.0.1.el5xen", rpm:"oracleasm-2.6.18-8.1.10.0.1.el5xen~2.0.4~1.el5", rls:"OracleLinux5"))) {
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
