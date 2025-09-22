# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-August/016890.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880569");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:59:00 +0000 (Fri, 14 Aug 2020)");
  script_xref(name:"CESA", value:"2010:0610");
  script_cve_id("CVE-2010-1084", "CVE-2010-2066", "CVE-2010-2070", "CVE-2010-2226",
                "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2524", "CVE-2006-0742");
  script_name("CentOS Update for kernel CESA-2010:0610 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * instances of unsafe sprintf() use were found in the Linux kernel
  Bluetooth implementation. Creating a large number of Bluetooth L2CAP, SCO,
  or RFCOMM sockets could result in arbitrary memory pages being overwritten.
  A local, unprivileged user could use this flaw to cause a kernel panic
  (denial of service) or escalate their privileges. (CVE-2010-1084,
  Important)

  * a flaw was found in the Xen hypervisor implementation when using the
  Intel Itanium architecture, allowing guests to enter an unsupported state.
  An unprivileged guest user could trigger this flaw by setting the BE (Big
  Endian) bit of the Processor Status Register (PSR), leading to the guest
  crashing (denial of service). (CVE-2010-2070, Important)

  * a flaw was found in the CIFSSMBWrite() function in the Linux kernel
  Common Internet File System (CIFS) implementation. A remote attacker could
  send a specially-crafted SMB response packet to a target CIFS client,
  resulting in a kernel panic (denial of service). (CVE-2010-2248, Important)

  * buffer overflow flaws were found in the Linux kernel's implementation of
  the server-side External Data Representation (XDR) for the Network File
  System (NFS) version 4. An attacker on the local network could send a
  specially-crafted large compound request to the NFSv4 server, which could
  possibly result in a kernel panic (denial of service) or, potentially, code
  execution. (CVE-2010-2521, Important)

  * a flaw was found in the handling of the SWAPEXT IOCTL in the Linux kernel
  XFS file system implementation. A local user could use this flaw to read
  write-only files, that they do not own, on an XFS file system. This could
  lead to unintended information disclosure. (CVE-2010-2226, Moderate)

  * a flaw was found in the dns_resolver upcall used by CIFS. A local,
  unprivileged user could redirect a Microsoft Distributed File System link
  to another IP address, tricking the client into mounting the share from a
  server of the user's choosing. (CVE-2010-2524, Moderate)

  * a missing check was found in the mext_check_arguments() function in the
  ext4 file system code. A local user could use this flaw to cause the
  MOVE_EXT IOCTL to overwrite the contents of an append-only file on an ext4
  file system, if they have write permissions for that file. (CVE-2010-2066,
  Low)

  Red Hat would like to thank Neil Brown for reporting CVE-2010-1084, and Dan
  Rosenberg for reporting CVE-2010-2226 and CVE-2010-2 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.11.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
