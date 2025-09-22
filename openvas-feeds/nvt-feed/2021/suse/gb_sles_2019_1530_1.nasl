# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1530.1");
  script_cve_id("CVE-2018-7191", "CVE-2019-10124", "CVE-2019-11085", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11487", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12382", "CVE-2019-3846", "CVE-2019-5489");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 19:53:50 +0000 (Tue, 04 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1530-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1530-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191530-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137752");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005572.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1530-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2019-11477: A sequence of SACKs may have been crafted such that one can trigger an integer overflow, leading to a kernel panic.
- CVE-2019-11478: It was possible to send a crafted sequence of SACKs which will fragment the TCP retransmission queue. An attacker may have been able to further exploit the fragmented queue to cause an expensive linked-list walk for subsequent SACKs received for that same TCP connection.
- CVE-2019-11479: An attacker could force the Linux kernel to segment its responses into multiple TCP segments. This would drastically increased the bandwidth required to deliver the same amount of data. Further, it would consume additional resources such as CPU and NIC processing power.
- CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the mwifiex kernel module while connecting to a malicious wireless network. (bnc#1136424)
- CVE-2019-12382: An issue was discovered in drm_load_edid_firmware in drivers/gpu/drm/drm_edid_load.c in the Linux kernel, there was an unchecked kstrdup of fwstr, which might have allowed an attacker to cause a denial of service (NULL pointer dereference and system crash). (bnc#1136586)
- CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux kernel allowed local attackers to observe page cache access patterns of other processes on the same system, potentially allowing sniffing of secret information. (Fixing this affects the output of the fincore program.) Limited remote exploitation may have been possible, as demonstrated by latency differences in accessing public files from an Apache HTTP Server. (bnc#1120843)
- CVE-2019-11487: The Linux kernel allowed page reference count overflow, with resultant use-after-free issues, if about 140 GiB of RAM existed. It could have occurred with FUSE requests. (bnc#1133190)
- CVE-2019-11833: fs/ext4/extents.c in the Linux kernel did not zero out the unused memory region in the extent tree block, which might have allowed local users to obtain sensitive information by reading uninitialized data in the filesystem. (bnc#1135281)
- CVE-2018-7191: In the tun subsystem in the Linux kernel, dev_get_valid_name was not called before register_netdevice. This allowed local users to cause a denial of service (NULL pointer dereference and panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. (bnc#1135603)
- CVE-2019-11085: Insufficient input validation in Kernel Mode Driver in i915 Graphics for Linux may have allowed an authenticated user to potentially enable escalation of privilege via local access. (bnc#1135278)
- CVE-2019-11815: An issue was discovered in rds_tcp_kill_sock in net/rds/tcp.c in the Linux kernel There was a race condition leading to a use-after-free, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.19.1", rls:"SLES12.0SP4"))) {
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
