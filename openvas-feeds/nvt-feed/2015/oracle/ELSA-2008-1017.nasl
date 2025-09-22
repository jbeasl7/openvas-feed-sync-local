# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122536");
  script_cve_id("CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4576");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:30 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-1017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-1017");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-1017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-92.1.22.0.1.el5, ofa-2.6.18-92.1.22.0.1.el5, oracleasm-2.6.18-92.1.22.0.1.el5' package(s) announced via the ELSA-2008-1017 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-92.1.22.0.1.el5]
- [net] Add entropy support to e1000 and bnx2 (John Sobecki) [orabug 6045759]
- [net] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]
- [mm] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- [nfs] nfs attribute timeout fix (Trond Myklebust) [orabug 7156607] [RHBZ 446083]
- [xen] execshield: fix endless GPF fault loop (Stephen Tweedie) [orabug 7175395]

[2.6.18-92.1.22.el5]
- [misc] hugepages: ia64 stack overflow and corrupt memory (Larry Woodman ) [474347 472802]
- [misc] allow hugepage allocation to use most of memory (Larry Woodman ) [474760 438889]

[2.6.18-92.1.21.el5]
- [misc] rtc: disable SIGIO notification on close (Vitaly Mayatskikh ) [465746 465747]

[2.6.18-92.1.20.el5]
- [input] atkbd: cancel delayed work before freeing struct (Jiri Pirko ) [461232 461233]
- [drm] i915 driver arbitrary ioremap (Eugene Teo ) [464508 464509] {CVE-2008-3831}
- [fs] don't allow splice to files opened with O_APPEND (Eugene Teo ) [466709 466710] {CVE-2008-4554}
- [xen] x86: allow the kernel to boot on pre-64 bit hw (Chris Lalancette ) [470040 468083]
- [net] ipv4: fix byte value boundary check (Jiri Pirko ) [469649 468148]
- [ia64] fix ptrace hangs when following threads (Denys Vlasenko ) [469150 461456]
- [net] sctp: INIT-ACK indicates no AUTH peer support oops (Eugene Teo ) [466081 466082] {CVE-2008-4576}
- [input] atkbd: delay executing of LED switching request (Jiri Pirko ) [461232 461233]
- [xen] ia64: make viosapic SMP-safe by adding lock/unlock (Tetsu Yamamoto ) [467727 466552]
- [xen] allow guests to hide the TSC from applications (Chris Lalancette ) [378471 378481] {CVE-2007-5907}
- [nfs] v4: don't reuse expired nfs4_state_owner structs (Jeff Layton ) [469650 441884]
- [nfs] v4: credential ref leak in nfs4_get_state_owner (Jeff Layton ) [469650 441884]
- [nfs] v4: Poll aggressively when handling NFS4ERR_DELAY (Jeff Layton ) [469650 441884]
- [xen] ia64: speed up hypercall for guest domain creation (Tetsu Yamamoto ) [459080 456171]
- [xen] use unlocked_ioctl in evtchn, gntdev and privcmd (Tetsu Yamamoto ) [459080 456171]
- [xen] page scrub: serialise softirq with a new lock (Tetsu Yamamoto ) [459080 456171]
- [xen] serialize scrubbing pages (Tetsu Yamamoto ) [459080 456171]
- [nfs] pages of a memory mapped file get corrupted (Peter Staubach ) [450335 435291]
- [x86_64] xen: fix syscall return when tracing (Chris Lalancette ) [470853 453394]

[2.6.18-92.1.19.el5]
- Revert: [xen] allow guests to hide the TSC from applications (Chris Lalancette ) [378471 378481] {CVE-2007-5907}
- Revert: [xen] x86: allow the kernel to boot on pre-64 bit hw (Chris Lalancette ) [470040 468083]

[2.6.18-92.1.18.el5]
- [xen] x86: allow the kernel to boot on pre-64 bit hw (Chris Lalancette ) [470040 468083]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-92.1.22.0.1.el5, ofa-2.6.18-92.1.22.0.1.el5, oracleasm-2.6.18-92.1.22.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~92.1.22.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.22.0.1.el5", rpm:"ocfs2-2.6.18-92.1.22.0.1.el5~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.22.0.1.el5PAE", rpm:"ocfs2-2.6.18-92.1.22.0.1.el5PAE~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.22.0.1.el5debug", rpm:"ocfs2-2.6.18-92.1.22.0.1.el5debug~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-92.1.22.0.1.el5xen", rpm:"ocfs2-2.6.18-92.1.22.0.1.el5xen~1.2.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.18-92.1.22.0.1.el5", rpm:"ofa-2.6.18-92.1.22.0.1.el5~1.3.1~5.20080603", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.18-92.1.22.0.1.el5PAE", rpm:"ofa-2.6.18-92.1.22.0.1.el5PAE~1.3.1~5.20080603", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.18-92.1.22.0.1.el5xen", rpm:"ofa-2.6.18-92.1.22.0.1.el5xen~1.3.1~5.20080603", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.22.0.1.el5", rpm:"oracleasm-2.6.18-92.1.22.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.22.0.1.el5PAE", rpm:"oracleasm-2.6.18-92.1.22.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.22.0.1.el5debug", rpm:"oracleasm-2.6.18-92.1.22.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-92.1.22.0.1.el5xen", rpm:"oracleasm-2.6.18-92.1.22.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
