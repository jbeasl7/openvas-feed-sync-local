# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3532.1");
  script_cve_id("CVE-2020-0404", "CVE-2020-0427", "CVE-2020-0430", "CVE-2020-0431", "CVE-2020-0432", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-14381", "CVE-2020-14390", "CVE-2020-16120", "CVE-2020-2521", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25641", "CVE-2020-25643", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-26088", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-30 17:14:46 +0000 (Mon, 30 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3532-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203532-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178838");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007871.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3532-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 LTSS kernel was updated to receive various security and bug fixes.


The following security bugs were fixed:

- CVE-2020-25705: A flaw in the way reply ICMP packets are limited in was found that allowed to quickly scan open UDP ports. This flaw allowed an off-path remote user to effectively bypassing source port UDP randomization. The highest threat from this vulnerability is to confidentiality and possibly integrity, because software and services that rely on UDP source port randomization (like DNS) are indirectly affected as well. Kernel versions may be vulnerable to this issue (bsc#1175721, bsc#1178782).
- CVE-2020-25704: Fixed a memory leak in perf_event_parse_addr_filter() (bsc#1178393).
- CVE-2020-25668: Fixed a use-after-free in con_font_op() (bnc#1178123).
- CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl (bnc#1177766).
- CVE-2020-25285: Fixed a race condition between hugetlb sysctl handlers in mm/hugetlb.c (bnc#1176485).
- CVE-2020-0430: Fixed an OOB read in skb_headlen of /include/linux/skbuff.h (bnc#1176723).
- CVE-2020-14351: Fixed a race in the perf_mmap_close() function (bsc#1177086).
- CVE-2020-16120: Fixed permission check to open real file when using overlayfs. It was possible to have a file not readable by an unprivileged user be copied to a mountpoint controlled by that user and then be able to access the file (bsc#1177470).
- CVE-2020-8694: Restricted energy meter to root access (bsc#1170415).
- CVE-2020-12351: Fixed a type confusion while processing AMP packets aka 'BleedingTooth' aka 'BadKarma' (bsc#1177724).
- CVE-2020-12352: Fixed an information leak when processing certain AMP packets aka 'BleedingTooth' (bsc#1177725).
- CVE-2020-25212: Fixed getxattr kernel panic and memory overflow (bsc#1176381).
- CVE-2020-25645: Fixed an issue in IPsec that caused traffic between two Geneve endpoints to be unencrypted (bnc#1177511).
- CVE-2020-2521: Fixed getxattr kernel panic and memory overflow (bsc#1176381).
- CVE-2020-14381: Fixed a use-after-free in the fast user mutex (futex) wait operation, which could have lead to memory corruption and possibly privilege escalation (bsc#1176011).
- CVE-2020-25643: Fixed a memory corruption and a read overflow which could have caused by improper input validation in the ppp_cp_parse_cr function (bsc#1177206).
- CVE-2020-25641: Fixed a zero-length biovec request issued by the block subsystem could have caused the kernel to enter an infinite loop, causing a denial of service (bsc#1177121).
- CVE-2020-26088: Fixed an improper CAP_NET_RAW check in NFC socket creation could have been used by local attackers to create raw sockets, bypassing security mechanisms (bsc#1176990).
- CVE-2020-14390: Fixed an out-of-bounds memory write leading to memory corruption or a denial of service when changing screen size (bnc#1176235).
- CVE-2020-0432: Fixed an out of bounds write due to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.63.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.63.1", rls:"SLES15.0"))) {
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
