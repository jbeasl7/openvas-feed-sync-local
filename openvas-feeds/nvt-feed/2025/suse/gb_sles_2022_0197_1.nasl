# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0197.1");
  script_cve_id("CVE-2020-27820", "CVE-2020-27825", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-33098", "CVE-2021-4001", "CVE-2021-4002", "CVE-2021-4083", "CVE-2021-4135", "CVE-2021-4149", "CVE-2021-4197", "CVE-2021-4202", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-44733", "CVE-2021-45485", "CVE-2021-45486", "CVE-2022-0185", "CVE-2022-0322");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-22 19:18:53 +0000 (Tue, 22 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0197-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0197-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220197-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194985");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-January/010080.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0197-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2022-0185: Incorrect param length parsing in legacy_parse_param which could have led to a local privilege escalation (bsc#1194517).
- CVE-2022-0322: Fixed a denial of service in SCTP sctp_addto_chunk (bsc#1194985).
- CVE-2021-44733: Fixed a use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel that occurred because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory object (bnc#1193767).
- CVE-2021-4197: Fixed a cgroup issue where lower privileged processes could write to fds of lower privileged ones that could lead to privilege escalation (bsc#1194302).
- CVE-2021-4135: Fixed an information leak in the nsim_bpf_map_alloc function (bsc#1193927).
- CVE-2021-4202: Fixed a race condition during NFC device remove which could lead to a use-after-free memory corruption (bsc#1194529)
- CVE-2021-4083: A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race condition. This flaw allowed a local user to crash the system or escalate their privileges on the system. (bnc#1193727).
- CVE-2021-4149: Fixed a locking condition in btrfs which could lead to system deadlocks (bsc#1194001).
- CVE-2021-45485: The IPv6 implementation in net/ipv6/output_core.c had an information leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based attackers can typically choose among many IPv6 source addresses (bnc#1194094).
- CVE-2021-45486: The IPv4 implementation in net/ipv4/route.c had an information leak because the hash table is very small (bnc#1194087).
- CVE-2021-4001: A race condition was found in the Linux kernel's ebpf verifier between bpf_map_update_elem and bpf_map_freeze due to a missing lock in kernel/bpf/syscall.c. In this flaw, a local user with a special privilege (cap_sys_admin or cap_bpf) can modify the frozen mapped address space. (bnc#1192990).
- CVE-2021-28715: Guest can force Linux netback driver to hog large amounts of kernel memory. Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is ready to process them. There are some measures taken for avoiding to pile up too much data, but those can be bypassed by the guest: There was a timeout how long the client side of an interface can stop consuming new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default). Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time. (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in its RX queue ring page and the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~24.99.1.9.46.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~24.99.1", rls:"SLES15.0SP2"))) {
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
