# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0437.1");
  script_cve_id("CVE-2019-19063", "CVE-2019-20934", "CVE-2019-6133", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-11668", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25211", "CVE-2020-25285", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-27068", "CVE-2020-27673", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-3347");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 02:12:54 +0000 (Thu, 09 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0437-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210437-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969755");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-February/008312.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:


- CVE-2021-3347: A use-after-free was discovered in the PI futexes during fault handling, allowing local users to execute code in the kernel (bnc#1181349).
- CVE-2020-29569: Fixed a potential privilege escalation and information leaks related to the PV block backend, as used by Xen (bnc#1179509).
- CVE-2020-29568: Fixed a denial of service issue, related to processing watch events (bnc#1179508).
- CVE-2020-25211: Fixed a flaw where a local attacker was able to inject conntrack netlink configuration that could cause a denial of service or trigger the use of incorrect protocol numbers in ctnetlink_parse_tuple_filter (bnc#1176395).
- CVE-2020-0444: Fixed a bad kfree due to a logic error in audit_data_to_entry (bnc#1180027).
- CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c that could have led to local privilege escalation (bnc#1180029).
- CVE-2020-0466: Fixed a use-after-free due to a logic error in do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).
- CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c which could have allowed local users to gain privileges or cause a denial of service (bsc#1179141).
- CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds check in the nl80211_policy policy of nl80211.c (bnc#1180086).
- CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction Services (RTAS) interface, affecting guests running on top of PowerVM or KVM hypervisors (bnc#1179107).
- CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation (bnc#1179601).
- CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls (bsc#1179960).
- CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).
- CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed a use-after-free attack against TIOCSPGRP (bsc#1179745).
- CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could have been used by local attackers to read privileged information or potentially crash the kernel (bsc#1178589).
- CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could have been used by local attackers to read kernel memory (bsc#1178886).
- CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit() (bsc#1178182).
- CVE-2020-25285: A race condition between hugetlb sysctl handlers in mm/hugetlb.c could be used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified other impact (bnc#1176485 ).
- CVE-2020-15437: Fixed a null pointer dereference which could have allowed local users to cause a denial of service (bsc#1179140).
- CVE-2020-36158: Fixed a potential remote code execution in the Marvell ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.149.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_149-default", rpm:"kgraft-patch-4_4_121-92_149-default~1~3.3.1", rls:"SLES12.0SP2"))) {
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
