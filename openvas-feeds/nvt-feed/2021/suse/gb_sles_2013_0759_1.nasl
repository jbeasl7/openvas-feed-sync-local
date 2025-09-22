# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0759.1");
  script_cve_id("CVE-2012-2137", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0349", "CVE-2013-0913", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1772", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-2634", "CVE-2013-2635");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0759-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0759-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130759-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:0759-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.74 fix various security issues and bugs:

This update brings some features:

 * Updated HD-audio drivers for Nvidia/AMD HDMI and Haswell audio (FATE#314311 FATE#313695)
 * Lustre enablement patches were added (FATE#314679).
 * SGI UV (Ultraviolet) platform support. (FATE#306952)

Security issues fixed in this update:

 * CVE-2013-0349: The hidp_setup_hid function in net/bluetooth/hidp/core.c in the Linux kernel did not properly copy a certain name field, which allowed local users to obtain sensitive information from kernel memory by setting a long name and making an HIDPCONNADD ioctl call.
 * CVE-2012-2137: Buffer overflow in virt/kvm/irq_comm.c in the KVM subsystem in the Linux kernel allowed local users to cause a denial of service (crash) and to possibly execute arbitrary code via vectors related to Message Signaled Interrupts (MSI), irq routing entries, and an incorrect check by the setup_routing_entry function before invoking the kvm_set_irq function.
 * CVE-2012-6549: The isofs_export_encode_fh function in fs/isofs/export.c in the Linux kernel did not initialize a certain structure member, which allowed local users to obtain sensitive information from kernel heap memory via a crafted application.
 * CVE-2012-6548: The udf_encode_fh function in fs/udf/namei.c in the Linux kernel did not initialize a certain structure member, which allowed local users to obtain sensitive information from kernel heap memory via a crafted application.
 * CVE-2013-0160: Timing side channel on attacks were possible on /dev/ptmx that could allow local attackers to predict keypresses like e.g. passwords. This has been fixed by not updating accessed/modified time on the pty devices.
Note that this might break pty idle detection, so it might get reverted again.
 * CVE-2013-0216: The Xen netback functionality in the Linux kernel allowed guest OS users to cause a denial of service (loop) by triggering ring pointer corruption.
 * CVE-2013-0231: The pciback_enable_msi function in the PCI backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for the Linux allowed guest OS users with PCI device access to cause a denial of service via a large number of kernel log messages.
 * CVE-2013-0311: The translate_desc function in drivers/vhost/vhost.c in the Linux kernel did not properly handle cross-region descriptors, which allowed guest OS users to obtain host OS privileges by leveraging KVM guest OS privileges.
 * CVE-2013-0913: Integer overflow in drivers/gpu/drm/i915/i915_gem_execbuffer.c in the i915 driver in the Direct Rendering Manager (DRM) subsystem in the Linux kernel allowed local users to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact via a crafted application that triggers many relocation copies, and potentially leads to a race condition.
 * CVE-2013-0914: The ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.74~0.6.6.2", rls:"SLES11.0SP2"))) {
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
