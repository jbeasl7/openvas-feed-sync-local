# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0559.1");
  script_cve_id("CVE-2019-14615", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16994", "CVE-2019-18808", "CVE-2019-19036", "CVE-2019-19045", "CVE-2019-19054", "CVE-2019-19066", "CVE-2019-19318", "CVE-2019-19319", "CVE-2019-19447", "CVE-2019-19767", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20095", "CVE-2019-20096", "CVE-2020-2732", "CVE-2020-7053", "CVE-2020-8428", "CVE-2020-8648", "CVE-2020-8992");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 15:01:42 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0559-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200559-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164735");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-March/006564.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:0559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-2732: Fixed an issue affecting Intel CPUs where an L2 guest may trick the L0 hypervisor into accessing sensitive L1 resources (bsc#1163971).
- CVE-2020-8992: An issue was discovered in ext4_protect_reserved_inode in fs/ext4/block_validity.c that allowed attackers to cause a soft lockup via a crafted journal size (bnc#1164069).
- CVE-2020-8648: There was a use-after-free vulnerability in the n_tty_receive_buf_common function in drivers/tty/n_tty.c (bnc#1162928).
- CVE-2020-8428: There was a use-after-free bug in fs/namei.c, which allowed local users to cause a denial of service or possibly obtain sensitive information from kernel memory (bnc#1162109).
- CVE-2020-7053: There was a use-after-free (write) in the i915_ppgtt_close function in drivers/gpu/drm/i915/i915_gem_gtt.c (bnc#1160966).
- CVE-2019-19045: A memory leak in drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c allowed attackers to cause a denial of service (memory consumption) by triggering mlx5_vector2eqn() failures (bnc#1161522).
- CVE-2019-16994: A memory leak existed in sit_init_net() in net/ipv6/sit.c which might have caused denial of service (bnc#1161523).
- CVE-2019-19054: A memory leak in the cx23888_ir_probe() function in drivers/media/pci/cx23885/cx23888-ir.c allowed attackers to cause a denial of service (memory consumption) by triggering kfifo_alloc() failures (bnc#1161518).
- CVE-2019-14896: A heap overflow was found in the add_ie_rates() function of the Marvell Wifi Driver (bsc#1157157).
- CVE-2019-14897: A stack overflow was found in the lbs_ibss_join_existing() function of the Marvell Wifi Driver (bsc#1157155).
- CVE-2019-19318: Mounting a crafted btrfs image twice could have caused a use-after-free (bnc#1158026).
- CVE-2019-19036: An issue discovered in btrfs_root_node in fs/btrfs/ctree.c allowed a NULL pointer dereference because rcu_dereference(root->node) can be zero (bnc#1157692).
- CVE-2019-14615: An information disclosure vulnerability existed due to insufficient control flow in certain data structures for some Intel(R) Processors (bnc#1160195).
- CVE-2019-19965: There was a NULL pointer dereference in drivers/scsi/libsas/sas_discover.c because of mishandling of port disconnection during discovery, related to a PHY down race condition (bnc#1159911).
- CVE-2019-20095: Fixed a memory leak and denial of service in mwifiex_tm_cmd in drivers/net/wireless/marvell/mwifiex/cfg80211.c, where some error-handling cases did not free allocated hostcmd memory (bnc#1159909).
- CVE-2019-20054: Fixed a NULL pointer dereference in drop_sysctl_table() in fs/proc/proc_sysctl.c related to put_links (bnc#1159910).
- CVE-2019-20096: Fixed a memory leak in __feat_register_sp() in net/dccp/feat.c, which may cause denial of service (bnc#1159908).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.37.1", rls:"SLES12.0SP4"))) {
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
