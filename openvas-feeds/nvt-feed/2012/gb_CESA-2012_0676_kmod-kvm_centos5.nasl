# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018649.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881216");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:48:06 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-1601", "CVE-2012-2121");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2012:0676");
  script_name("CentOS Update for kmod-kvm CESA-2012:0676 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kmod-kvm on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module built for
  the standard Red Hat Enterprise Linux kernel.

  A flaw was found in the way the KVM_CREATE_IRQCHIP ioctl was handled.
  Calling this ioctl when at least one virtual CPU (VCPU) already existed
  could lead to a NULL pointer dereference later when the VCPU is scheduled
  to run. A malicious user in the kvm group on the host could use this flaw
  to crash the host. (CVE-2012-1601)

  A flaw was found in the way device memory was handled during guest device
  removal. Upon successful device removal, memory used by the device was not
  properly unmapped from the corresponding IOMMU or properly released from
  the kernel, leading to a memory leak. A malicious user in the kvm group on
  the host who has the ability to assign a device to a guest could use this
  flaw to crash the host. (CVE-2012-2121)

  This update also fixes the following bug:

  * An off-by-one error in the QEMU guest's memory management could, in rare
  cases, cause QEMU-KVM to crash due to a segmentation fault in
  tb_invalidate_phys_page_range() if a device initiated DMA into a specific
  guest address. In a reported case, this issue presented on a system that
  had a guest using the 8139cp network driver. (BZ#816207)

  All users of kvm are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. Note that the procedure
  in the Solution section must be performed before this update will take
  effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~249.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~249.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~249.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~249.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~249.el5.centos.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
