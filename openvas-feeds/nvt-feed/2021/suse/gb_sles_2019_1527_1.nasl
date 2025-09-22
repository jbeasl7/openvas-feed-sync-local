# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1527.1");
  script_cve_id("CVE-2013-4343", "CVE-2018-17972", "CVE-2018-7191", "CVE-2019-11190", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11815", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-12382", "CVE-2019-3846", "CVE-2019-5489");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 19:53:50 +0000 (Tue, 04 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1527-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1527-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191527-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843419");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005576.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1527-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.180 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-11477: A sequence of SACKs may have been crafted such that one can
 trigger an integer overflow, leading to a kernel panic. (bsc#1137586)

- CVE-2019-11478: It was possible to send a crafted sequence of SACKs which
 will fragment the TCP retransmission queue. An attacker may have been able to
 further exploit the fragmented queue to cause an expensive linked-list walk
 for subsequent SACKs received for that same TCP connection.

- CVE-2019-11479: It was possible to send a crafted sequence of SACKs which
 will fragment the RACK send map. A remote attacker may be able to further
 exploit the fragmented send map to cause an expensive linked-list walk for
 subsequent SACKs received for that same TCP connection. This would have
 resulted in excess resource consumption due to low mss values.

- CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and possibly
 escalate privileges was found in the mwifiex kernel module while connecting
 to a malicious wireless network. (bnc#1136424)

- CVE-2019-12382: An issue was discovered in drm_load_edid_firmware in
 drivers/gpu/drm/drm_edid_load.c in the Linux kernel There was an unchecked
 kstrdup of fwstr, which might allow an attacker to cause a denial of service
 (NULL pointer dereference and system crash). (bnc#1136586)

- CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux
 kernel allowed local attackers to observe page cache access patterns of other
 processes on the same system, potentially allowing sniffing of secret
 information. (Fixing this affects the output of the fincore program.) Limited
 remote exploitation may be possible, as demonstrated by latency differences
 in accessing public files from an Apache HTTP Server. (bnc#1120843).

- CVE-2019-11833: fs/ext4/extents.c in the Linux kernel did not zero out the
 unused memory region in the extent tree block, which might allow local users
 to obtain sensitive information by reading uninitialized data in the
 filesystem. (bnc#1135281)

- CVE-2018-7191: In the tun subsystem in the Linux kernel before 4.13.14,
 dev_get_valid_name is not called before register_netdevice. This allowed
 local users to cause a denial of service (NULL pointer dereference and panic)
 via an ioctl(TUNSETIFF) call with a dev name containing a / character. This
 is similar to CVE-2013-4343. (bnc#1135603)

- CVE-2019-11190: The Linux kernel allowed local users to bypass ASLR on setuid
 programs (such as /bin/su) because install_exec_creds() is called too late in
 load_elf_binary() in fs/binfmt_elf.c, and thus the ptrace_may_access() check
 has a race condition when reading /proc/pid/stat. (bnc#1131543)

- CVE-2019-11815: An issue was discovered in rds_tcp_kill_sock in net/rds/tcp.c
 in the Linux kernel There was a race ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.4.180~4.31.1", rls:"SLES12.0SP3"))) {
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
