# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2332.1");
  script_cve_id("CVE-2016-8405", "CVE-2017-13305", "CVE-2018-1000204", "CVE-2018-1068", "CVE-2018-1130", "CVE-2018-12233", "CVE-2018-13053", "CVE-2018-13406", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5803", "CVE-2018-5814", "CVE-2018-7492");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-27 13:59:42 +0000 (Mon, 27 Aug 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2332-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182332-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909361");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-August/004417.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-3620: Local attackers on baremetal systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data, even from other virtual machines or the host system. (bnc#1089343).
- CVE-2018-1000204: A malformed SG_IO ioctl issued for a SCSI device could lead to a local kernel information leak manifesting in up to approximately 1000 memory pages copied to the userspace. The problem has limited scope as non-privileged users usually have no permissions to access SCSI device files. (bnc#1096728).
- CVE-2018-13053: The alarm_timer_nsleep function in kernel/time/alarmtimer.c had an integer overflow via a large relative timeout because ktime_add_safe is not used (bnc#1099924).
- CVE-2018-13406: An integer overflow in the uvesafb_setcmap function in drivers/video/fbdev/uvesafb.c could result in local attackers being able to crash the kernel or potentially elevate privileges because kmalloc_array is not used (bnc#1098016 bnc#1100418).
- CVE-2016-8405: An information disclosure vulnerability in kernel components including the ION subsystem, Binder, USB driver and networking subsystem could enable a local malicious application to access data outside of its permission levels. (bnc#1099942).
- CVE-2018-5814: Multiple race condition errors when handling probe, disconnect, and rebind operations could be exploited to trigger a use-after-free condition or a NULL pointer dereference by sending multiple USB over IP packets (bnc#1096480).
- CVE-2018-12233: In the ea_get function in fs/jfs/xattr.c a memory corruption bug in JFS can be triggered by calling setxattr twice with two different extended attribute names on the same file. This vulnerability can be triggered by an unprivileged user with the ability to create files and execute programs. (bnc#1097234).
- CVE-2017-13305: A information disclosure vulnerability in the Upstream kernel encrypted-keys. (bnc#1094353).
- CVE-2018-1130: A null pointer dereference in dccp_write_xmit() function in net/dccp/output.c allowed a local user to cause a denial of service by a number of certain crafted system calls (bnc#1092904).
- CVE-2018-1068: A flaw was found in the implementation of 32-bit syscall interface for bridging. This allowed a privileged user to arbitrarily write to a limited range of kernel memory (bnc#1085107).
- CVE-2018-5803: An error in the '_sctp_make_chunk()' function (net/sctp/sm_make_chunk.c) when handling ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.68.1", rls:"SLES11.0SP4"))) {
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
