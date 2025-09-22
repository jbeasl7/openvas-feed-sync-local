# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1366.1");
  script_cve_id("CVE-2018-1000199", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1065", "CVE-2018-1130", "CVE-2018-3639", "CVE-2018-5803", "CVE-2018-7492", "CVE-2018-8781");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-06 17:29:56 +0000 (Wed, 06 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1366-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1366-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181366-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981348");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/004070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1366-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.131 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-3639: Information leaks using 'Memory Disambiguation' feature
 in modern CPUs were mitigated, aka 'Spectre Variant 4' (bnc#1087082).

 A new boot commandline option was introduced,
 'spec_store_bypass_disable', which can have following values:

 - auto: Kernel detects whether your CPU model contains an implementation
 of Speculative Store Bypass and picks the most appropriate mitigation.
 - on: disable Speculative Store Bypass
 - off: enable Speculative Store Bypass
 - prctl: Control Speculative Store Bypass per thread via
 prctl. Speculative Store Bypass is enabled for a process by default. The
 state of the control is inherited on fork.
 - seccomp: Same as 'prctl' above, but all seccomp threads will disable
 SSB unless they explicitly opt out.

 The default is 'seccomp', meaning programs need explicit opt-in into the mitigation.

 Status can be queried via the /sys/devices/system/cpu/vulnerabilities/spec_store_bypass file, containing:

 - 'Vulnerable'
 - 'Mitigation: Speculative Store Bypass disabled'
 - 'Mitigation: Speculative Store Bypass disabled via prctl'
 - 'Mitigation: Speculative Store Bypass disabled via prctl and seccomp'


- CVE-2018-8781: The udl_fb_mmap function in drivers/gpu/drm/udl/udl_fb.c
 had an integer-overflow vulnerability allowing local users with access
 to the udldrmfb driver to obtain full read and write permissions on
 kernel physical pages, resulting in a code execution in kernel space
 (bnc#1090643).
- CVE-2018-10124: The kill_something_info function in kernel/signal.c
 might have allowed local users to cause a denial of service via an
 INT_MIN argument (bnc#1089752).
- CVE-2018-10087: The kernel_wait4 function in kernel/exit.c might
 have allowed local users to cause a denial of service by triggering an
 attempted use of the -INT_MIN value (bnc#1089608).
- CVE-2018-1000199: An address corruption flaw was discovered while
 modifying a h/w breakpoint via 'modify_user_hw_breakpoint' routine, an
 unprivileged user/process could use this flaw to crash the system kernel
 resulting in DoS OR to potentially escalate privileges on a the system. (bsc#1089895)
- CVE-2018-1130: The Linux kernel was vulnerable to a null pointer
 dereference in dccp_write_xmit() function in net/dccp/output.c in that
 allowed a local user to cause a denial of service by a number of certain
 crafted system calls (bnc#1092904).
- CVE-2018-5803: An error in the _sctp_make_chunk() function when handling
 SCTP, packet length could have been exploited by a malicious local user
 to cause a kernel crash and a DoS. (bnc#1083900).
- CVE-2018-1065: The netfilter subsystem mishandled the case of
 a rule blob that contains a jump but lacks a user-defined chain,
 which allowed local users to cause a denial of service (NULL
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.131~94.29.1", rls:"SLES12.0SP3"))) {
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
