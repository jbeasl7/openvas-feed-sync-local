# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882388");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-02 06:14:07 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2016-1714");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libcacard CESA-2016:0083 centos7");
  script_tag(name:"summary", value:"Check the version of libcacard");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a
full virtualization solution for Linux on AMD64 and Intel 64 systems.
The qemu-kvm package provides the user-space component for running virtual
machines using KVM.

An out-of-bounds read/write flaw was discovered in the way QEMU's Firmware
Configuration device emulation processed certain firmware configurations.
A privileged (CAP_SYS_RAWIO) guest user could use this flaw to crash the
QEMU process instance or, potentially, execute arbitrary code on the host
with privileges of the QEMU process. (CVE-2016-1714)

Red Hat would like to thank Donghai Zhu of Alibaba for reporting this
issue.

This update also fixes the following bugs:

  * Incorrect handling of the last sector of an image file could trigger an
assertion failure in qemu-img. This update changes the handling of the last
sector, and no assertion failure occurs. (BZ#1298828)

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.");
  script_tag(name:"affected", value:"libcacard on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0083");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-February/021637.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcacard-devel", rpm:"libcacard-devel~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcacard-tools", rpm:"libcacard-tools~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~105.el7_2.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
