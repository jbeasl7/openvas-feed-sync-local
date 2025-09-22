# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0789.1");
  script_cve_id("CVE-2011-4131", "CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2373", "CVE-2012-2375", "CVE-2012-2390");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0789-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0789-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120789-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:0789-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.34, fixing a lot of bugs and security issues.

The update from Linux kernel 3.0.31 to 3.0.34 also fixes various bugs not listed here.

The following security issues have been fixed:

 *

 CVE-2012-2136: Local attackers could trigger an overflow in sock_alloc_send_pksb(), potentially crashing the machine or escalate privileges.

 *

 CVE-2012-2390: A memory leak in transparent hugepages on mmap failure could be used by local attacker to run the machine out of memory (local denial of service).

 *

 CVE-2012-2119: A malicious guest driver could overflow the host stack by passing a long descriptor, so potentially crashing the host system or escalating privileges on the host.

 *

 CVE-2012-2375: Malicious NFS server could crash the clients when more than 2 GETATTR bitmap words are returned in response to the FATTR4_ACL attribute requests, only incompletely fixed by CVE-2011-4131.

The following non-security bugs have been fixed:


Hyper-V:

 * storvsc: Properly handle errors from the host
(bnc#747404).
 * HID: hid-hyperv: Do not use hid_parse_report()
directly.
 * HID: hyperv: Set the hid drvdata correctly.
 * drivers/hv: Get rid of an unnecessary check in vmbus_prep_negotiate_resp().
 * drivers/hv: util: Properly handle version negotiations.
 * hv: fix return type of hv_post_message().
 * net/hyperv: Add flow control based on hi/low watermark.
 * usb/net: rndis: break out defines. only net/hyperv part
 * usb/net: rndis: remove ambigous status codes. only net/hyperv part
 * usb/net: rndis: merge command codes. only net/hyperv part
 * net/hyperv: Adding cancellation to ensure rndis filter is closed.
 * update hv drivers to 3.4-rc1, requires new hv_kvp_daemon:
 * drivers: hv: kvp: Add/cleanup connector defines.
 * drivers: hv: kvp: Move the contents of hv_kvp.h to hyperv.h.
 * net/hyperv: Convert camel cased variables in rndis_filter.c to lower cases.
 * net/hyperv: Correct the assignment in netvsc_recv_callback().
 * net/hyperv: Remove the unnecessary memset in rndis_filter_send().
 * drivers: hv: Cleanup the kvp related state in hyperv.h.
 * tools: hv: Use hyperv.h to get the KVP definitions.
 * drivers: hv: kvp: Cleanup the kernel/user protocol.
 * drivers: hv: Increase the number of VCPUs supported in the guest.
 * net/hyperv: Fix data corruption in rndis_filter_receive().
 * net/hyperv: Add support for vlan trunking from guests.
 * Drivers: hv: Add new message types to enhance KVP.
 * Drivers: hv: Support the newly introduced KVP messages in the driver.
 * Tools: hv: Fully support the new KVP verbs in the user level daemon.
 * Tools: hv: Support enumeration from all the pools.
 * net/hyperv: Fix the code handling tx busy.
 * patches.suse/suse-hv-pata_piix-ignore-disks.patch replace our version of this patch with upstream variant:
ata_piix: defer disks to the Hyper-V drivers by default libata: add a host flag to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise High Availability Extension 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.34~0.7.9", rls:"SLES11.0SP2"))) {
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
