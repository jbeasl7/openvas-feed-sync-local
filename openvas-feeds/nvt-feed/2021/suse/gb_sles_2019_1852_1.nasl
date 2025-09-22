# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1852.1");
  script_cve_id("CVE-2018-20836", "CVE-2019-10126", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11487", "CVE-2019-11599", "CVE-2019-12380", "CVE-2019-12456", "CVE-2019-12614", "CVE-2019-12818", "CVE-2019-12819");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-17 14:11:17 +0000 (Mon, 17 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1852-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191852-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140577");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-10638: In the Linux kernel, a device could be tracked by an attacker using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and ICMP). When such traffic was sent to multiple destination IP addresses, it was possible to obtain hash collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). An attack may have been conducted by hosting a crafted web page that uses WebRTC or gQUIC to force UDP traffic to attacker-controlled IP addresses (bnc#1140575 1140577).
- CVE-2019-10639: The Linux kernel allowed Information Exposure (partial kernel address disclosure), that lead to a KASLR bypass. Specifically, it was possible to extract the KASLR kernel image offset using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and ICMP). When such traffic is sent to multiple destination IP addresses, it was possible to obtain hash collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). This key contains enough bits from a kernel address (of a static variable) so when the key is extracted (via enumeration), the offset of the kernel image is exposed. This attack could be carried out remotely, by the attacker forcing the target device to send UDP or ICMP (or certain other) traffic to attacker-controlled IP addresses. Forcing a server to send UDP traffic is trivial if the server is a DNS server. ICMP traffic is trivial if the server answers ICMP Echo requests (ping). For client targets, if the target visited the attacker's web page, then WebRTC or gQUIC could be used to force UDP traffic to attacker-controlled IP addresses. NOTE: this attack against KASLR became viable because IP ID generation was changed to have a dependency on an address associated with a network namespace (bnc#1140577).
- CVE-2019-10126: A flaw was found in the Linux kernel. A heap based buffer overflow in mwifiex_uap_parse_tail_ies function in drivers/net/wireless/marvell/mwifiex/ie.c might have lead to memory corruption and possibly other consequences (bnc#1136935).
- CVE-2018-20836: An issue was discovered in the Linux kernel There was a race condition in smp_task_timedout() and smp_task_done() in drivers/scsi/libsas/sas_expander.c, leading to a use-after-free (bnc#1134395).
- CVE-2019-11599: The coredump implementation in the Linux kernel did not use locking or other mechanisms to prevent vma layout or vma flags changes while it ran, which allowed local users to obtain sensitive information, cause a denial of service, or possibly have unspecified other impact by triggering a race condition with mmget_not_zero or get_task_mm call. This is related to fs/userfaultfd.c, mm/mmap.c, fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.100.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_100-default", rpm:"kgraft-patch-4_4_180-94_100-default~1~4.3.1", rls:"SLES12.0SP3"))) {
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
