# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0115.2");
  script_cve_id("CVE-2010-3873", "CVE-2010-4164", "CVE-2010-4249", "CVE-2011-1080", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-3209");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:29 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2012-05-25 15:18:00 +0000 (Fri, 25 May 2012)");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0115-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0115-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120115-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0115-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Linux kernel update fixes various security issues and bugs in the SUSE Linux Enterprise 10 SP4 kernel.

This update fixes the following security issues:

 * bnc#651219: X.25 remote DoS (CVE-2010-3873)
 * bnc#653260: X.25 remote Dos (CVE-2010-4164)
 * bnc#655696: 1 socket local DoS (CVE-2010-4249)
 * bnc#676602: ebtables infoleak (CVE-2011-1080)
 * bnc#681180: netfilter: arp_tables infoleak to userspace (CVE-2011-1170)
 * bnc#681181: netfilter: ip_tables infoleak to userspace (CVE-2011-1171)
 * bnc#681185: netfilter: ip6_tables infoleak to userspace (CVE-2011-1172)
 * bnc#681186: econet 4 byte infoleak (CVE-2011-1173)
 * bnc#699709: hfs NULL pointer dereference
(CVE-2011-2203)
 * bnc#700879: inet_diag infinite loop (CVE-2011-2213)
 * bnc#702037: netfilter: ipt_CLUSTERIP buffer overflow
(CVE-2011-2534)
 * bnc#707288: ipv6: make fragment identifications less predictable (CVE-2011-2699)
 * bnc#726064: clock_gettime() panic (CVE-2011-3209)
 * bnc#735612: qdisc NULL dereference (CVE-2011-2525)

This update also fixes the following non-security issues:

 * bnc#671124: New timesource for VMware platform
 * bnc#673343: usblp crashes after the printer is unplugged for the second time
 * bnc#704253: Data corruption with mpt2sas driver
 * bnc#716437: NIC Bond no longer works when booting the XEN kernel
 * bnc#721267: 'reboot=b' kernel command line hangs system on reboot
 * bnc#721351: kernel panic at iscsi_xmitwork function
 * bnc#725878: NFS supplementary group permissions
 * bnc#726843: IBM LTC System z Maintenance Kernel Patches (#59)
 * bnc#727597: NFS slowness
 * bnc#728341: IBM LTC System z maintenance kernel patches (#60)
 * bnc#729117: propagate MAC-address to VLAN-interface
 * bnc#730749: ipmi deadlock in start_next_msg
 * bnc#731770: ext3 filesystem corruption after crash
 * bnc#732375: IBM LTC System z maintenance kernel patches (#61)
 * bnc#733407: hangs when offlining a CPU core

Security Issue references:

 * CVE-2011-2534
>
 * CVE-2011-2525
>
 * CVE-2011-2203
>
 * CVE-2011-2699
>
 * CVE-2010-4249
>
 * CVE-2011-1173
>
 * CVE-2011-1170
>
 * CVE-2011-1171
>
 * CVE-2010-3873
>
 * CVE-2011-1080
>
 * CVE-2011-2213
>
 * CVE-2011-3209
>
 * CVE-2011-1172
>
 * CVE-2010-4164
>");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.93.1", rls:"SLES10.0SP4"))) {
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
