# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2152.1");
  script_cve_id("CVE-2019-20810", "CVE-2019-20812", "CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10711", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10773", "CVE-2020-12771", "CVE-2020-13974", "CVE-2020-14416");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-15 18:42:18 +0000 (Mon, 15 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2152-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202152-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174543");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-August/007235.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2152-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-10135: Legacy pairing and secure-connections pairing authentication in Bluetooth may have allowed an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key (bnc#1171988).
- CVE-2020-10711: A NULL pointer dereference flaw was found in the SELinux subsystem. This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. This flaw allowed a remote network user to crash the system kernel, resulting in a denial of service (bnc#1171191).
- CVE-2020-10751: A flaw was found in the SELinux LSM hook implementation, where it incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly only validate the first netlink message in the skb and allow or deny the rest of the messages within the skb with the granted permission without further processing (bnc#1171189).
- CVE-2019-20812: An issue was discovered in the prb_calc_retire_blk_tmo() function in net/packet/af_packet.c can result in a denial of service (CPU consumption and soft lockup) in a certain failure case involving TPACKET_V3, aka CID-b43d1f9f7067 (bnc#1172453).
- CVE-2020-10732: A flaw was found in the implementation of userspace core dumps. This flaw allowed an attacker with a local account to crash a trivial program and exfiltrate private kernel data (bnc#1171220).
- CVE-2020-0305: In cdev_get of char_dev.c, there is a possible use-after-free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation (bnc#1174462).
- CVE-2020-12771: btree_gc_coalesce in drivers/md/bcache/btree.c had a deadlock if a coalescing operation fails (bnc#1171732).
- CVE-2020-10773: A kernel stack information leak on s390/s390x was fixed (bnc#1172999).
- CVE-2020-14416: A race condition in tty->disc_data handling in the slip and slcan line discipline could lead to a use-after-free, aka CID-0ace17d56824. This affects drivers/net/slip/slip.c and drivers/net/can/slcan.c (bnc#1162002).
- CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer overflow if k_ascii is called several times in a row, aka CID-b86dab054059. (bnc#1172775).
- CVE-2019-20810: go7007_snd_init in drivers/media/usb/go7007/snd-go7007.c in the Linux kernel did not call snd_card_free for a failure path, which causes a memory leak, aka CID-9453264ef586 (bnc#1172458).

The following non-security bugs were fixed:

- Drivers: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-kgraft", rpm:"kernel-default-kgraft~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.180~94.127.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_127-default", rpm:"kgraft-patch-4_4_180-94_127-default~1~4.3.1", rls:"SLES12.0SP3"))) {
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
