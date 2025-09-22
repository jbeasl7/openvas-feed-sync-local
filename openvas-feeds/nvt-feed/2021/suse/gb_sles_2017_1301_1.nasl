# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1301.1");
  script_cve_id("CVE-2015-3288", "CVE-2015-8970", "CVE-2016-10200", "CVE-2016-5243", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-7184", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-31 18:12:52 +0000 (Fri, 31 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1301-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171301-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999245");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002880.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

Notable new features:

- Toleration of newer crypto hardware for z Systems
- USB 2.0 Link power management for Haswell-ULT

The following security bugs were fixed:

- CVE-2017-7308: The packet_set_ring function in net/packet/af_packet.c in the Linux kernel did not properly validate certain block-size data, which allowed local users to cause a denial of service (overflow) or possibly have unspecified other impact via crafted system calls (bnc#1031579)
- CVE-2017-2671: The ping_unhash function in net/ipv4/ping.c in the Linux kernel was too late in obtaining a certain lock and consequently could not ensure that disconnect function calls are safe, which allowed local users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a socket system call (bnc#1031003)
- CVE-2017-7184: The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel did not validate certain size data after an XFRM_MSG_NEWAE update, which allowed local users to obtain root privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN capability (bsc#1030573).
- CVE-2017-5970: The ipv4_pktinfo_prepare function in net/ipv4/ip_sockglue.c in the Linux kernel allowed attackers to cause a denial of service (system crash) via (1) an application that made crafted system calls or possibly (2) IPv4 traffic with invalid IP options (bsc#1024938).
- CVE-2017-7616: Incorrect error handling in the set_mempolicy and mbind compat syscalls in mm/mempolicy.c in the Linux kernel allowed local users to obtain sensitive information from uninitialized stack data by triggering failure of a certain bitmap operation (bsc#1033336).
- CVE-2017-7294: The vmw_surface_define_ioctl function in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not validate addition of certain levels data, which allowed local users to trigger an integer overflow and out-of-bounds write, and cause a denial of service (system hang or crash) or possibly gain privileges, via a crafted ioctl call for a /dev/dri/renderD* device (bnc#1031440)
- CVE-2017-7261: The vmw_surface_define_ioctl function in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not check for a zero value of certain levels data, which allowed local users to cause a denial of service (ZERO_SIZE_PTR dereference, and GPF and possibly panic) via a crafted ioctl call for a /dev/dri/renderD* device (bnc#1031052)
- CVE-2017-7187: The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel allowed local users to cause a denial of service (stack-based buffer overflow) or possibly have unspecified other impact via a large command size in an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds write access in the sg_write function (bnc#1030213)
- CVE-2017-6348: The ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~100.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~100.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~100.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~100.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~100.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~100.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~100.1", rls:"SLES11.0SP4"))) {
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
