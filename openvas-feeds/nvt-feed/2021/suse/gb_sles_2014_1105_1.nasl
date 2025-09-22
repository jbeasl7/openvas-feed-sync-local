# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1105.1");
  script_cve_id("CVE-2013-4299", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-1739", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-5077");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1105-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1105-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141105-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2014:1105-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 SP2 LTSS received a roll up update to fix several security and non-security issues.

The following security issues have been fixed:

 * CVE-2014-0055: The get_rx_bufs function in drivers/vhost/net.c in
 the vhost-net subsystem in the Linux kernel package before
 2.6.32-431.11.2 on Red Hat Enterprise Linux (RHEL) 6 does not
 properly handle vhost_get_vq_desc errors, which allows guest OS
 users to cause a denial of service (host OS crash) via unspecified
 vectors. (bnc#870173)
 * CVE-2014-0077: drivers/vhost/net.c in the Linux kernel before
 3.13.10, when mergeable buffers are disabled, does not properly
 validate packet lengths, which allows guest OS users to cause a
 denial of service (memory corruption and host OS crash) or possibly
 gain privileges on the host OS via crafted packets, related to the
 handle_rx and get_rx_bufs functions. (bnc#870576)
 * CVE-2014-1739: The media_device_enum_entities function in
 drivers/media/media-device.c in the Linux kernel before 3.14.6 does
 not initialize a certain data structure, which allows local users to
 obtain sensitive information from kernel memory by leveraging
/dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call.
(bnc#882804)
 * CVE-2014-2706: Race condition in the mac80211 subsystem in the Linux
 kernel before 3.13.7 allows remote attackers to cause a denial of
 service (system crash) via network traffic that improperly interacts
 with the WLAN_STA_PS_STA state (aka power-save mode), related to
 sta_info.c and tx.c. (bnc#871797)
 * CVE-2014-2851: Integer overflow in the ping_init_sock function in
 net/ipv4/ping.c in the Linux kernel through 3.14.1 allows local
 users to cause a denial of service (use-after-free and system crash)
 or possibly gain privileges via a crafted application that leverages
 an improperly managed reference counter. (bnc#873374)
 * CVE-2014-3144: The (1) BPF_S_ANC_NLATTR and (2)
 BPF_S_ANC_NLATTR_NEST extension implementations in the sk_run_filter
 function in net/core/filter.c in the Linux kernel through 3.14.3 do
 not check whether a certain length value is sufficiently large,
 which allows local users to cause a denial of service (integer
 underflow and system crash) via crafted BPF instructions. NOTE: the
 affected code was moved to the __skb_get_nlattr and
 __skb_get_nlattr_nest functions before the vulnerability was
 announced. (bnc#877257)
 * CVE-2014-3145: The BPF_S_ANC_NLATTR_NEST extension implementation in
 the sk_run_filter function in net/core/filter.c in the Linux kernel
 through 3.14.3 uses the reverse order in a certain subtraction,
 which allows local users to cause a denial of service (over-read and
 system crash) via crafted BPF instructions. NOTE: the affected code
 was moved to the __skb_get_nlattr_nest function before the
 vulnerability was announced. (bnc#877257)
 * CVE-2014-3917: kernel/auditsc.c in the Linux kernel through ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.7.23.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.6_06_3.0.101_0.7.23~0.5.30", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.6_06_3.0.101_0.7.23~0.5.30", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.6_06_3.0.101_0.7.23~0.5.30", rls:"SLES11.0SP2"))) {
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
