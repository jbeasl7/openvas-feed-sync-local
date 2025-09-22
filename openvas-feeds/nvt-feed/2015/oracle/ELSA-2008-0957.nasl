# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122545");
  script_cve_id("CVE-2006-5755", "CVE-2007-5907", "CVE-2008-2372", "CVE-2008-3276", "CVE-2008-3527", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:43 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 20:24:38 +0000 (Thu, 15 Feb 2024)");

  script_name("Oracle: Security Advisory (ELSA-2008-0957)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0957");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0957.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-92.1.17.0.1.el5, oracleasm-2.6.18-92.1.17.0.1.el5' package(s) announced via the ELSA-2008-0957 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-92.1.17.0.1.el5]
- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [NFS] nfs attribute timeout fix (Trond Myklebust) [orabug 7156607] [RHBZ 446083]
- [NET] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]
- [NET] fix netpoll race (Tina Yang) [orabugz 5791]

[2.6.18-92.1.17.el5]

- Revert: [nfs] pages of a memory mapped file get corrupted (Peter Staubach ) [450335 435291]

[2.6.18-92.1.16.el5]

- [i386] vDSO: use install_special_mapping (Peter Zijlstra ) [460275 460276] {CVE-2008-3527}
- [scsi] aacraid: remove some quirk AAC_QUIRK_SCSI_32 bits (Tomas Henzl ) [466885 453472]
- [fs] remove SUID when splicing into an inode (Eric Sandeen ) [464451 464452] {CVE-2008-3833}
- [fs] open() allows setgid bit when user is not in group (Eugene Teo ) [463867 463687] {CVE-2008-4210}
- [xen] ia64: fix INIT injection (Tetsu Yamamoto ) [467105 464445]

[2.6.18-92.1.15.el5]

- [pci] fix problems with msi interrupt management (Neil Horman ) [461894 428696]
- [x86_64] revert time syscall changes (Prarit Bhargava ) [466427 461184]
- [xen] allow guests to hide the TSC from applications (Chris Lalancette ) [378471 378481] {CVE-2007-5907}
- [scsi] qla2xxx: additional residual-count correction (Marcus Barrow ) [465741 462117]
- [char] add range_is_allowed check to mmap_mem (Eugene Teo ) [460858 460857]
- [fs] binfmt_misc: avoid potential kernel stack overflow (Vitaly Mayatskikh ) [459464 459463]
- [misc] cpufreq: fix format string bug (Vitaly Mayatskikh ) [459461 459460]
- [dlm] user.c input validation fixes (David Teigland ) [458759 458760]
- [nfs] pages of a memory mapped file get corrupted (Peter Staubach ) [450335 435291]
- [x86_64] gettimeofday fixes for HPET, PMTimer, TSC (Prarit Bhargava ) [462860 250708]

[2.6.18-92.1.14.el5]

- [libata] ata_scsi_rbuf_get check for scatterlist usage (David Milburn ) [460638 455445]
- [net] random32: seeding improvement (Jiri Pirko ) [458021 458019]
- [x86_64] xen: local DOS due to NT bit leakage (Eugene Teo ) [457721 457722] {CVE-2006-5755}
- [fs] cifs: fix O_APPEND on directio mounts (Jeff Layton ) [462591 460063]
- [openib] race between QP async handler and destroy_qp (Brad Peters ) [458781 446109]
- [net] dccp_setsockopt_change integer overflow (Vitaly Mayatskikh ) [459232 459235] {CVE-2008-3276}
- [acpi] error attaching device data (peterm@redhat.com ) [460868 459670]
- [mm] optimize ZERO_PAGE in 'get_user_pages' and fix XIP (Anton Arapov ) [452667 452668] {CVE-2008-2372}
- [xen] xennet: coordinate ARP with backend network status (Herbert Xu ) [461457 458934]
- [xen] event channel lock and barrier (Markus Armbruster ) [461099 457086]
- [fs] fix bad unlock_page in pip_to_file() error path (Larry Woodman ) [462436 439917]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-92.1.17.0.1.el5, oracleasm-2.6.18-92.1.17.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.17.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.17.0.1.el5", rpm:"ocfs2-2.6.18-92.1.17.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.17.0.1.el5PAE", rpm:"ocfs2-2.6.18-92.1.17.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.17.0.1.el5debug", rpm:"ocfs2-2.6.18-92.1.17.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.17.0.1.el5xen", rpm:"ocfs2-2.6.18-92.1.17.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.17.0.1.el5", rpm:"oracleasm-2.6.18-92.1.17.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.17.0.1.el5PAE", rpm:"oracleasm-2.6.18-92.1.17.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.17.0.1.el5debug", rpm:"oracleasm-2.6.18-92.1.17.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.17.0.1.el5xen", rpm:"oracleasm-2.6.18-92.1.17.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
