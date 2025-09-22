# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123567");
  script_cve_id("CVE-2012-3511", "CVE-2013-2141", "CVE-2013-4162");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1292");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1292.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-348.18.1.el5, oracleasm-2.6.18-348.18.1.el5' package(s) announced via the ELSA-2013-1292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-348.18.1]
- [net] be2net: enable polling prior enabling interrupts globally (Ivan Vecera) [1005239 987539]
- [kernel] signals: stop info leak via tkill and tgkill syscalls (Oleg Nesterov) [970874 970875] {CVE-2013-2141}
- [net] ipv6: do udp_push_pending_frames AF_INET sock pending data (Jiri Benc) [987647 987648] {CVE-2013-4162}
- [mm] use-after-free in madvise_remove() (Jacob Tanenbaum) [849735 849736] {CVE-2012-3511}
- [fs] autofs: remove autofs dentry mount check (Ian Kent) [1001488 928098]

[2.6.18-348.17.1]
- [net] be2net: Fix to avoid hardware workaround when not needed (Ivan Vecera) [999819 995961]
- [net] be2net: Mark checksum fail for IP fragmented packets (Ivan Vecera) [983864 956322]
- [net] be2net: Avoid double insertion of vlan tags (Ivan Vecera) [983864 956322]
- [net] be2net: disable TX in be_close() (Ivan Vecera) [983864 956322]
- [net] be2net: fix EQ from getting full while cleaning RX CQ (Ivan Vecera) [983864 956322]
- [net] be2net: avoid napi_disable() when not enabled (Ivan Vecera) [983864 956322]
- [net] be2net: Fix receive Multicast Packets w/ Promiscuous mode (Ivan Vecera) [983864 956322]
- [net] be2net: Fixed memory leak (Ivan Vecera) [983864 956322]
- [net] be2net: Fix PVID tag offload for packets w/ inline VLAN tag (Ivan Vecera) [983864 956322]
- [net] be2net: fix a Tx stall bug caused by a specific ipv6 packet (Ivan Vecera) [983864 956322]
- [net] be2net: Remove an incorrect pvid check in Tx (Ivan Vecera) [983864 956322]
- [net] be2net: Fix issues in error recovery with wrong queue state (Ivan Vecera) [983864 956322]
- [net] netpoll: revert 6bdb7fe3104 and fix be_poll() instead (Ivan Vecera) [983864 956322]
- [net] be2net: Fix to parse RSS hash Receive completions correctly (Ivan Vecera) [983864 956322]
- [net] be2net: Fix cleanup path when EQ creation fails (Ivan Vecera) [983864 956322]
- [net] be2net: Fix Endian (Ivan Vecera) [983864 956322]
- [net] be2net: Fix to trim skb for padded vlan packets (Ivan Vecera) [983864 956322]
- [net] be2net: Explicitly clear reserved field in Tx Descriptor (Ivan Vecera) [983864 956322]
- [net] be2net: remove unnecessary usage of unlikely() (Ivan Vecera) [983864 956322]
- [net] be2net: do not modify PCI MaxReadReq size (Ivan Vecera) [983864 956322]
- [net] be2net: cleanup be_vid_config() (Ivan Vecera) [983864 956322]
- [net] be2net: don't call vid_config() when there no vlan config (Ivan Vecera) [983864 956322]
- [net] be2net: Ignore status of some ioctls during driver load (Ivan Vecera) [983864 956322]
- [net] be2net: Fix wrong status getting returned for MCC commands (Ivan Vecera) [983864 956322]
- [net] be2net: Fix VLAN/multicast packet reception (Ivan Vecera) [983864 956322]
- [net] be2net: fix wrong frag_idx reported by RX CQ (Ivan Vecera) [983864 956322]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-348.18.1.el5, oracleasm-2.6.18-348.18.1.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.18.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.18.1.el5", rpm:"ocfs2-2.6.18-348.18.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.18.1.el5PAE", rpm:"ocfs2-2.6.18-348.18.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.18.1.el5debug", rpm:"ocfs2-2.6.18-348.18.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-348.18.1.el5xen", rpm:"ocfs2-2.6.18-348.18.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.18.1.el5", rpm:"oracleasm-2.6.18-348.18.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.18.1.el5PAE", rpm:"oracleasm-2.6.18-348.18.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.18.1.el5debug", rpm:"oracleasm-2.6.18-348.18.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-348.18.1.el5xen", rpm:"oracleasm-2.6.18-348.18.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
