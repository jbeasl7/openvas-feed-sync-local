# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882173");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-04-23 07:33:46 +0200 (Thu, 23 Apr 2015)");
  script_cve_id("CVE-2014-8106");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for qemu-guest-agent CESA-2015:0867 centos6");
  script_tag(name:"summary", value:"Check the version of qemu-guest-agent");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full
 virtualization solution for
Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides the
user-space component for running virtual machines using KVM.

It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of VRAM-
allocated buffer boundaries in the host's QEMU process address space with
attacker-provided data. (CVE-2014-8106)

This issue was found by Paolo Bonzini of Red Hat.

This update also fixes the following bug:

  * Previously, the effective downtime during the last phase of a live
migration would sometimes be much higher than the maximum downtime
specified by 'migration_downtime' in vdsm.conf. This problem has been
corrected. The value of 'migration_downtime' is now honored and the
migration is aborted if the downtime cannot be achieved. (BZ#1142756)

All qemu-kvm users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.");
  script_tag(name:"affected", value:"qemu-guest-agent on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0867");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-April/021082.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.448.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.448.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.448.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.448.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
