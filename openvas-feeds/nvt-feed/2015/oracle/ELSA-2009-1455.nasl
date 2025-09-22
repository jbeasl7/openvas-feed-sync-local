# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122433");
  script_cve_id("CVE-2009-2849");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:17 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1455");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1455.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.2.1.0.1.el5, oracleasm-2.6.18-164.2.1.0.1.el5' package(s) announced via the ELSA-2009-1455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.2.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb ( John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]

[2.6.18-164.2.1.el5]
- [x86_64] kvm: bound last_kvm to prevent backwards time (Glauber Costa ) [524527 524076]
- [x86] kvm: fix vsyscall going backwards (Glauber Costa ) [524527 524076]
- [misc] fix RNG to not use first generated random block (Neil Horman ) [523289 522860]
- [x86] kvm: mark kvmclock_init as cpuinit (Glauber Costa ) [524151 523450]
- [x86_64] kvm: allow kvmclock to be overwritten (Glauber Costa ) [524150 523447]
- [x86] kvmclock: fix bogus wallclock value (Glauber Costa ) [524152 519771]
- [scsi] scsi_dh_rdace: add more sun hardware (mchristi@redhat.com ) [523237 518496]
- [misc] cprng: fix cont test to be fips compliant (Neil Horman ) [523290 523259]
- [net] bridge: fix LRO crash with tun (Andy Gospodarek ) [522636 483646]
- Revert: [x86_64] fix gettimeoday TSC overflow issue - 1 (Don Zickus ) [489847 467942]
- Revert: [net] atalk/irda: memory leak to user in getname (Danny Feng ) [519309 519310] {CVE-2009-3001 CVE-2009-3002}

[2.6.18-164.1.1.el5]
- [net] sky2: revert some phy power refactoring changes (Neil Horman ) [517976 509891]
- [net] atalk/irda: memory leak to user in getname (Danny Feng ) [519309 519310] {CVE-2009-3001 CVE-2009-3002}
- [x86_64] fix gettimeoday TSC overflow issue - 1 (Prarit Bhargava ) [489847 467942]
- [md] prevent crash when accessing suspend_* sysfs attr (Danny Feng ) [518135 518136] {CVE-2009-2849}
- [nfs] nlm_lookup_host: don't return invalidated nlm_host (Sachin S. Prabhu ) [517967 507549]
- [net] bonding: tlb/alb: set active slave when enslaving (Jiri Pirko ) [517971 499884]
- [nfs] r/w I/O perf degraded by FLUSH_STABLE page flush (Peter Staubach ) [521244 498433]
- [SELinux] allow preemption b/w transition perm checks (Eric Paris ) [520919 516216]
- [scsi] scsi_transport_fc: fc_user_scan correction (David Milburn ) [521239 515176]
- [net] tg3: refrain from touching MPS (John Feeney ) [521241 516123]
- [net] qlge: fix hangs and read performance (Marcus Barrow ) [519783 517893]
- [scsi] qla2xxx: allow use of MSI when MSI-X disabled (Marcus Barrow ) [519782 517922]
- [net] mlx4_en fix for vlan traffic (Doug Ledford ) [520906 514141]
- [net] mlx4_core: fails to load on large systems (Doug Ledford ) [520908 514147]
- [x86] disable kvmclock by default (Glauber Costa ) [520685 476075]
- [x86] disable kvmclock when shutting the machine down (Glauber Costa ) [520685 476075]
- [x86] ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.2.1.0.1.el5, oracleasm-2.6.18-164.2.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.2.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.2.1.0.1.el5", rpm:"ocfs2-2.6.18-164.2.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.2.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-164.2.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.2.1.0.1.el5debug", rpm:"ocfs2-2.6.18-164.2.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.2.1.0.1.el5xen", rpm:"ocfs2-2.6.18-164.2.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.2.1.0.1.el5", rpm:"oracleasm-2.6.18-164.2.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.2.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-164.2.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.2.1.0.1.el5debug", rpm:"oracleasm-2.6.18-164.2.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.2.1.0.1.el5xen", rpm:"oracleasm-2.6.18-164.2.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
