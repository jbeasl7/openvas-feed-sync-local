# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123194");
  script_cve_id("CVE-2014-4171", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-7145", "CVE-2014-7822", "CVE-2014-7841");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-0102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0102");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0102.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2015-0102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.10.0-123.20.1]
- Oracle Linux certificates (Alexey Petrenko)

[3.10.0-123.20.1]
- [fs] seq_file: don't include mm.h in genksyms calculation (Ian Kent) [1184152 1183280]

[3.10.0-123.19.1]
- [mm] shmem: fix splicing from a hole while it's punched (Denys Vlasenko) [1118244 1118245] {CVE-2014-4171}
- [mm] shmem: fix faulting into a hole, not taking i_mutex (Denys Vlasenko) [1118244 1118245] {CVE-2014-4171}
- [mm] shmem: fix faulting into a hole while it's punched (Denys Vlasenko) [118244 1118245] {CVE-2014-4171}
- [x86] traps: stop using IST for #SS (Petr Matousek) [1172812 1172813] {CVE-2014-9322}
- [net] vxlan: fix incorrect initializer in union vxlan_addr (Daniel Borkmann) [1156611 1130643]
- [net] vxlan: fix crash when interface is created with no group (Daniel Borkmann) [1156611 1130643]
- [net] vxlan: fix nonfunctional neigh_reduce() (Daniel Borkmann) [1156611 1130643]
- [net] vxlan: fix potential NULL dereference in arp_reduce() (Daniel Borkmann) [1156611 1130643]
- [net] vxlan: remove unused port variable in vxlan_udp_encap_recv() (Daniel Borkmann) [1156611 1130643]
- [net] vxlan: remove extra newline after function definition (Daniel Borkmann) [1156611 1130643]
- [net] etherdevice: Use ether_addr_copy to copy an Ethernet address (Stefan Assmann) [1156611 1091126]
- [fs] splice: perform generic write checks (Eric Sandeen) [1163799 1155907] {CVE-2014-7822}
- [fs] eliminate BUG() call when there's an unexpected lock on file close (Frank Sorenson) [1172266 1148130]
- [net] sctp: fix NULL pointer dereference in af->from_addr_param on malformed packet (Daniel Borkmann) [1163094 1154002] {CVE-2014-7841}
- [fs] lockd: Try to reconnect if statd has moved (Benjamin Coddington) [1150889 1120850]
- [fs] sunrpc: Don't wake tasks during connection abort (Benjamin Coddington) [1150889 1120850]
- [fs] cifs: NULL pointer dereference in SMB2_tcon (Jacob Tanenbaum) [1147528 1147529] {CVE-2014-7145}
- [net] ipv6: addrconf: implement address generation modes (Jiri Pirko) [1144876 1107369]
- [net] gre: add link local route when local addr is any (Jiri Pirko) [1144876 1107369]
- [net] gre6: don't try to add the same route two times (Jiri Pirko) [1144876 1107369]
- [fs] isofs: unbound recursion when processing relocated directories (Jacob Tanenbaum) [1142270 1142271] {CVE-2014-5471 CVE-2014-5472}
- [fs] fs: seq_file: fallback to vmalloc allocation (Ian Kent) [1140302 1095623]
- [fs] fs: /proc/stat: convert to single_open_size() (Ian Kent) [1140302 1095623]
- [fs] fs: seq_file: always clear m->count when we free m->buf (Ian Kent) [1140302 1095623]

[3.10.0-123.18.1]
- [net] ipv6: fib: fix fib dump restart (Panu Matilainen) [1172795 1163605]
- [net] ipv6: drop unused fib6_clean_all_ro() function and rt6_proc_arg struct (Panu Matilainen) [1172795 1163605]
- [net] ipv6: avoid high order memory allocations for /proc/net/ipv6_route (Panu Matilainen) [1172795 1163605]
- [mm] numa: Remove ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.20.1.el7", rls:"OracleLinux7"))) {
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
