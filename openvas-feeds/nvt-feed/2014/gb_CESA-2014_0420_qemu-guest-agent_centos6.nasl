# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881925");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2014-05-02 10:05:16 +0530 (Fri, 02 May 2014)");
  script_cve_id("CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145",
                "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-03 14:26:00 +0000 (Mon, 03 Oct 2022)");
  script_name("CentOS Update for qemu-guest-agent CESA-2014:0420 centos6");

  script_tag(name:"affected", value:"qemu-guest-agent on CentOS 6");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides the
user-space component for running virtual machines using KVM.

Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An attacker
able to modify a disk image file loaded by a guest could use these flaws to
crash the guest, or corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges of
the QEMU process. (CVE-2014-0143, CVE-2014-0144, CVE-2014-0145,
CVE-2014-0147)

A buffer overflow flaw was found in the way the virtio_net_handle_mac()
function of QEMU processed guest requests to update the table of MAC
addresses. A privileged guest user could use this flaw to corrupt QEMU
process memory on the host, potentially resulting in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-0150)

A divide-by-zero flaw was found in the seek_to_sector() function of the
parallels block driver in QEMU. An attacker able to modify a disk image
file loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0142)

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest could
use this flaw to crash the guest. (CVE-2014-0146)

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a missing
bounds check. An attacker able to modify a disk image file loaded by a
guest could use this flaw to crash the guest. (CVE-2014-0148)

The CVE-2014-0143 issues were discovered by Kevin Wolf and Stefan Hajnoczi
of Red Hat, the CVE-2014-0144 issues were discovered by Fam Zheng, Jeff
Cody, Kevin Wolf, and Stefan Hajnoczi of Red Hat, the CVE-2014-0145 issues
were discovered by Stefan Hajnoczi of Red Hat, the CVE-2014-0150 issue was
discovered by Michael S. Tsirkin of Red Hat, the CVE-2014-0142,
CVE-2014-0146, and CVE-2014-0147 issues were discovered by Kevin Wolf of
Red Hat, and the CVE-2014-0148 issue was discovered by Jeff Cody of
Red Hat.

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0420");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-April/020262.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-guest-agent'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
