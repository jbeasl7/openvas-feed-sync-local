# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123082");
  script_cve_id("CVE-2011-5321", "CVE-2015-1593", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3636");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:07 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1221");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-1221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504.30.3]
- [redhat] spec: Update dracut dependency to pull in drbg module (Frantisek Hrbata) [1241517 1241338]

[2.6.32-504.30.2]
- [crypto] rng: Remove krng (Herbert Xu) [1233512 1226418]
- [crypto] drbg: Add stdrng alias and increase priority (Herbert Xu) [1233512 1226418]
- [crypto] seqiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418]
- [crypto] eseqiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418]
- [crypto] chainiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418]

[2.6.32-504.30.1]
- [net] Fix checksum features handling in netif_skb_features() (Vlad Yasevich) [1231690 1220247]

[2.6.32-504.29.1]
- [net] gso: fix skb_segment for non-offset skb pointers (Jiri Benc) [1229586 1200533]

[2.6.32-504.28.1]
- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202860 1185166] {CVE-2015-1805}
- [net] ipv4: Missing sk_nulls_node_init in ping_unhash (Denys Vlasenko) [1218102 1218103] {CVE-2015-3636}
- [net] conntrack: RFC5961 challenge ACK confuse conntrack LAST-ACK transition (Jesper Brouer) [1227467 1227468 1212801 1200541]
- [net] tcp: Restore RFC5961-compliant behavior for SYN packets (Jesper Brouer) [1227467 1227468 1212801 1200541]
- [x86] kernel: ignore NMI IOCK when in kdump kernel (Jerry Snitselaar) [1225054 1196263]
- [x86] asm/entry/64: Remove a bogus 'ret_from_fork' optimization (Mateusz Guzik) [1209232 1209233] {CVE-2015-2830}
- [fs] gfs2: try harder to obtain journal lock during recovery (Abhijith Das) [1222588 1110846]
for core_pmu (Jiri Olsa) [1219149 1188336]
- [x86] mm: Linux stack ASLR implementation (Jacob Tanenbaum) [1195682 1195683] {CVE-2015-1593}
- [fs] xfs: DIO write completion size updates race (Brian Foster) [1218499 1198440]
- [net] ipv6: Don't reduce hop limit for an interface (Denys Vlasenko) [1208492 1208493]
- [net] vlan: more careful checksum features handling (Vlad Yasevich) [1221844 1212384]
- [kernel] tracing: Export tracing clock functions (Jerry Snitselaar) [1217986 1212502]
- [edac] sb_edac: fix corruption/crash on imbalanced Haswell home agents (Seth Jennings) [1213468 1210148]
- [netdrv] tun: Fix csum_start with VLAN acceleration (Jason Wang) [1217189 1036482]
- [netdrv] tun: unbreak truncated packet signalling (Jason Wang) [1217189 1036482]
- [netdrv] tuntap: hardware vlan tx support (Jason Wang) [1217189 1036482]
- [vhost] vhost-net: fix handle_rx buffer size (Jason Wang) [1217189 1036482]
- [netdrv] ixgbe: fix X540 Completion timeout (John Greene) [1215855 1150343]
- [char] tty: drop driver reference in tty_open fail path (Mateusz Guzik) [1201893 1201894]
- [netdrv] macvtap: Fix csum_start when VLAN tags are present (Vlad Yasevich) [1215914 1123697]
- [netdrv] macvtap: signal truncated packets (Vlad Yasevich) [1215914 1123697]
- [netdrv] macvtap: restore vlan header on user read (Vlad Yasevich) [1215914 1123697]
- [netdrv] macvlan: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.30.3.el6", rls:"OracleLinux6"))) {
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
