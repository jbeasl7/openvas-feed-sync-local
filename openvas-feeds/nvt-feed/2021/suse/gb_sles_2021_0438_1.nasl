# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0438.1");
  script_cve_id("CVE-2019-20806", "CVE-2019-20934", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-10781", "CVE-2020-11668", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25211", "CVE-2020-25639", "CVE-2020-25669", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-27835", "CVE-2020-28374", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29371", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2020-4788", "CVE-2021-3347", "CVE-2021-3348");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 02:12:54 +0000 (Thu, 09 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0438-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0438-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210438-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179895");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181645");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-February/008317.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0438-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2021-3348: Fixed a use-after-free in nbd_add_socket that could be triggered by local attackers (with access to the nbd device) via an I/O request at a certain point during device setup (bnc#1181504).
- CVE-2021-3347: A use-after-free was discovered in the PI futexes during fault handling, allowing local users to execute code in the kernel (bnc#1181349).
- CVE-2020-25211: Fixed a buffer overflow in ctnetlink_parse_tuple_filter() which could be triggered by a local attackers by injecting conntrack netlink configuration (bnc#1176395).
- CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was found, specifically in the way user calls Ioctl after open dev file and fork. A local user could use this flaw to crash the system (bnc#1179878).
- CVE-2020-29569: Fixed a potential privilege escalation and information leaks related to the PV block backend, as used by Xen (bnc#1179509).
- CVE-2020-29568: Fixed a denial of service issue, related to processing watch events (bnc#1179508).
- CVE-2020-0444: Fixed a bad kfree due to a logic error in audit_data_to_entry (bnc#1180027).
- CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c that could have led to local privilege escalation (bnc#1180029).
- CVE-2020-0466: Fixed a use-after-free due to a logic error in do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).
- CVE-2020-4788: Fixed an issue with IBM Power9 processors could have allowed a local user to obtain sensitive information from the data in the L1 cache under extenuating circumstances (bsc#1177666).
- CVE-2020-10781: A flaw was found in the ZRAM kernel module, where a user with a local account and the ability to read the /sys/class/zram-control/hot_add file can create ZRAM device nodes in the /dev/ directory. This read allocates kernel memory and is not accounted for a user that triggers the creation of that ZRAM device. With this vulnerability, continually reading the device may consume a large amount of system memory and cause the Out-of-Memory (OOM) killer to activate and terminate random userspace processes, possibly making the system inoperable (bnc#1173074).
- CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c which could have allowed local users to gain privileges or cause a denial of service (bsc#1179141).
- CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds check in the nl80211_policy policy of nl80211.c (bnc#1180086).
- CVE-2020-25639: Fixed a NULL pointer dereference via nouveau ioctl (bnc#1176846).
- CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction Services (RTAS) interface, affecting guests running on top of PowerVM or KVM hypervisors (bnc#1179107).
- CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150.66.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150.66.1", rls:"SLES15.0"))) {
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
