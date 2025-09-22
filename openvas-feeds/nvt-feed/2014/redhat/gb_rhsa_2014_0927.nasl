# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871210");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-28 16:45:49 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151",
                "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4535", "CVE-2013-4536",
                "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182",
                "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3461");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)");
  script_name("RedHat Update for qemu-kvm RHSA-2014:0927-01");


  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides the
user-space component for running virtual machines using KVM.

Two integer overflow flaws were found in the QEMU block driver for QCOW
version 1 disk images. A user able to alter the QEMU disk image files
loaded by a guest could use either of these flaws to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-0222, CVE-2014-0223)

Multiple buffer overflow, input validation, and out-of-bounds write flaws
were found in the way virtio, virtio-net, virtio-scsi, usb, and hpet
drivers of QEMU handled state loading after migration. A user able to alter
the savevm data (either on the disk or over the wire during migration)
could use either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2013-4148, CVE-2013-4149, CVE-2013-4150, CVE-2013-4151, CVE-2013-4527,
CVE-2013-4529, CVE-2013-4535, CVE-2013-4536, CVE-2013-4541, CVE-2013-4542,
CVE-2013-6399, CVE-2014-0182, CVE-2014-3461)

These issues were discovered by Michael S. Tsirkin, Anthony Liguori and
Michael Roth of Red Hat: CVE-2013-4148, CVE-2013-4149, CVE-2013-4150,
CVE-2013-4151, CVE-2013-4527, CVE-2013-4529, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, and
CVE-2014-3461.

This update also fixes the following bugs:

  * Previously, QEMU did not free pre-allocated zero clusters correctly and
the clusters under some circumstances leaked. With this update,
pre-allocated zero clusters are freed appropriately and the cluster leaks
no longer occur. (BZ#1110188)

  * Prior to this update, the QEMU command interface did not properly handle
resizing of cache memory during guest migration, causing QEMU to terminate
unexpectedly with a segmentation fault and QEMU to fail. This update fixes
the related code and QEMU no longer crashes in the described situation.
(BZ#1110191)

  * Previously, when a guest device was hot unplugged, QEMU correctly removed
the corresponding file descriptor watch but did not re-create it after the
device was re-connected. As a consequence, the guest became unable to
receive any data from the host over this device. With this update, the file
descriptor's watch is re-created and the guest in the above scenario can
communicate with the host as expected. (BZ#1110219)

  * Previously, the Q ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0927-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-July/msg00053.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.5", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
