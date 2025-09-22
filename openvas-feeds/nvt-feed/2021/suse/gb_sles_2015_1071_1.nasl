# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1071.1");
  script_cve_id("CVE-2014-3647", "CVE-2014-8086", "CVE-2014-8159", "CVE-2015-1465", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3332", "CVE-2015-3339", "CVE-2015-3636");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-05-27 16:32:06 +0000 (Wed, 27 May 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1071-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151071-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931130");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001441.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:1071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to version 3.12.43 to receive various security and bugfixes.

Following security bugs were fixed:

- CVE-2014-3647: arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel through 3.17.2 did not properly perform RIP changes, which allowed guest OS users to cause a denial of service (guest OS crash) via a crafted application (bsc#899192).
- CVE-2014-8086: Race condition in the ext4_file_write_iter function in fs/ext4/file.c in the Linux kernel through 3.17 allowed local users to cause a denial of service (file unavailability) via a combination of a write action and an F_SETFL fcntl operation for the O_DIRECT flag (bsc#900881).
- CVE-2014-8159: The InfiniBand (IB) implementation did not properly restrict use of User Verbs for registration of memory regions, which allowed local users to access arbitrary physical memory locations, and consequently cause a denial of service (system crash) or gain privileges, by leveraging permissions on a uverbs device under /dev/infiniband/ (bsc#914742).
- CVE-2015-1465: The IPv4 implementation in the Linux kernel before 3.18.8 did not properly consider the length of the Read-Copy Update (RCU) grace period for redirecting lookups in the absence of caching, which allowed remote attackers to cause a denial of service (memory consumption or system crash) via a flood of packets (bsc#916225).
- CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux kernel before 3.19 used an incorrect data type in a sysctl table, which allowed local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry (bsc#919007).
- CVE-2015-2042: net/rds/sysctl.c in the Linux kernel before 3.19 used an incorrect data type in a sysctl table, which allowed local users to obtain potentially sensitive information from kernel memory or possibly have unspecified other impact by accessing a sysctl entry (bsc#919018).
- CVE-2015-2666: Fixed a flaw that allowed crafted microcode to overflow the kernel stack (bsc#922944).
- CVE-2015-2830: Fixed int80 fork from 64-bit tasks mishandling (bsc#926240).
- CVE-2015-2922: Fixed possible denial of service (DoS) attack against IPv6 network stacks due to improper handling of Router Advertisements (bsc#922583).
- CVE-2015-3331: Fixed buffer overruns in RFC4106 implementation using AESNI (bsc#927257).
- CVE-2015-3332: Fixed TCP Fast Open local DoS (bsc#928135).
- CVE-2015-3339: Fixed race condition flaw between the chown() and execve() system calls which could have lead to local privilege escalation (bsc#928130).
- CVE-2015-3636: Fixed use-after-free in ping sockets which could have lead to local privilege escalation (bsc#929525).

The following non-security bugs were fixed:

- /proc/stat: convert to single_open_size() (bsc#928122).
- ACPI / sysfs: Treat the count field of counter_show() as unsigned ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.43~52.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.43~52.6.1", rls:"SLES12.0"))) {
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
