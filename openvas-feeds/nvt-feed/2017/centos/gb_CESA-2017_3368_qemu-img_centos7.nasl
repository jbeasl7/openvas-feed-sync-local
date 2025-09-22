# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882812");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-07 07:39:28 +0100 (Thu, 07 Dec 2017)");
  script_cve_id("CVE-2017-14167", "CVE-2017-15289");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for qemu-img CESA-2017:3368 centos7");
  script_tag(name:"summary", value:"Check the version of qemu-img");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kernel-based Virtual Machine (KVM) is a
full virtualization solution for Linux on a variety of architectures.
The qemu-kvm package provides the user-space component for running virtual
machines that use KVM.

Security Fix(es):

  * Quick Emulator (QEMU), compiled with the PC System Emulator with
multiboot feature support, is vulnerable to an OOB r/w memory access issue.
The issue could occur due to an integer overflow while loading a kernel
image during a guest boot. A user or process could use this flaw to
potentially achieve arbitrary code execution on a host. (CVE-2017-14167)

  * Quick emulator (QEMU), compiled with the Cirrus CLGD 54xx VGA Emulator
support, is vulnerable to an OOB write access issue. The issue could occur
while writing to VGA memory via mode4and5 write functions. A privileged
user inside guest could use this flaw to crash the QEMU process resulting
in Denial of service (DoS). (CVE-2017-15289)

Red Hat would like to thank Thomas Garnier (Google.com) for reporting
CVE-2017-14167 and Guoxiang Niu (Huawei.com) for reporting CVE-2017-15289.");
  script_tag(name:"affected", value:"qemu-img on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:3368");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-December/022679.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~141.el7_4.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~141.el7_4.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~141.el7_4.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~141.el7_4.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
