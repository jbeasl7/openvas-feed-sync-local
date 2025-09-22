# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0812.1");
  script_cve_id("CVE-2009-4020", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1585", "CVE-2011-4127", "CVE-2011-4132", "CVE-2011-4913", "CVE-2011-4914", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-3400", "CVE-2012-6657", "CVE-2013-2147", "CVE-2013-4299", "CVE-2013-6405", "CVE-2013-6463", "CVE-2014-0181", "CVE-2014-1874", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3673", "CVE-2014-3917", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9420", "CVE-2014-9584", "CVE-2015-2041");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-12-17 17:41:59 +0000 (Wed, 17 Dec 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0812-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150812-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:0812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 10 SP4 LTSS kernel was updated to receive various security and bugfixes.
The following security bugs have been fixed:
CVE-2015-2041: A information leak in the llc2_timeout_table was fixed (bnc#919007).
CVE-2014-9322: arch/x86/kernel/entry_64.S in the Linux kernel did not properly handle faults associated with the Stack Segment (SS) segment register, which allowed local users to gain privileges by triggering an IRET instruction that leads to access to a GS Base address from the wrong space (bnc#910251).
CVE-2014-9090: The do_double_fault function in arch/x86/kernel/traps.c in the Linux kernel did not properly handle faults associated with the Stack Segment (SS) segment register, which allowed local users to cause a denial of service (panic) via a modify_ldt system call, as demonstrated by sigreturn_32 in the 1-clock-tests test suite (bnc#907818).
CVE-2014-4667: The sctp_association_free function in net/sctp/associola.c in the Linux kernel did not properly manage a certain backlog value, which allowed remote attackers to cause a denial of service (socket outage) via a crafted SCTP packet (bnc#885422).
CVE-2014-3673: The SCTP implementation in the Linux kernel allowed remote attackers to cause a denial of service (system crash) via a malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c and net/sctp/sm_statefuns.c (bnc#902346).
CVE-2014-3185: Multiple buffer overflows in the command_port_read_callback function in drivers/usb/serial/whiteheat.c in the Whiteheat USB Serial Driver in the Linux kernel allowed physically proximate attackers to execute arbitrary code or cause a denial of service (memory corruption and system crash) via a crafted device that provides a large amount of (1) EHCI or (2) XHCI data associated with a bulk response (bnc#896391).
CVE-2014-3184: The report_fixup functions in the HID subsystem in the Linux kernel might have allowed physically proximate attackers to cause a denial of service (out-of-bounds write) via a crafted device that provides a small report descriptor, related to (1) drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3) drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c, (5) drivers/hid/hid-petalynx.c, and (6) drivers/hid/hid-sunplus.c (bnc#896390).
CVE-2014-1874: The security_context_to_sid_core function in security/selinux/ss/services.c in the Linux kernel allowed local users to cause a denial of service (system crash) by leveraging the CAP_MAC_ADMIN capability to set a zero-length security context (bnc#863335).
CVE-2014-0181: The Netlink implementation in the Linux kernel did not provide a mechanism for authorizing socket operations based on the opener of a socket, which allowed local users to bypass intended access restrictions and modify network configurations by using a Netlink socket for the (1) stdout or (2) stderr of a setuid program (bnc#875051).
CVE-2013-4299: Interpretation conflict in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.132.1", rls:"SLES10.0SP4"))) {
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
