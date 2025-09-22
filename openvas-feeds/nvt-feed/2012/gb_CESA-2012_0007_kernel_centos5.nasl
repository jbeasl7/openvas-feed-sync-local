# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-January/018370.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881222");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:50:27 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1020", "CVE-2011-3637", "CVE-2011-4077", "CVE-2011-4132",
                "CVE-2011-4324", "CVE-2011-4325", "CVE-2011-4330", "CVE-2011-4348",
                "CVE-2011-2482");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:35:00 +0000 (Fri, 31 Jul 2020)");
  script_xref(name:"CESA", value:"2012:0007");
  script_name("CentOS Update for kernel CESA-2012:0007 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A buffer overflow flaw was found in the way the Linux kernel's XFS file
  system implementation handled links with overly long path names. A local,
  unprivileged user could use this flaw to cause a denial of service or
  escalate their privileges by mounting a specially-crafted disk.
  (CVE-2011-4077, Important)

  * The fix for CVE-2011-2482 provided by RHSA-2011:1212 introduced a
  regression: on systems that do not have Security-Enhanced Linux (SELinux)
  in Enforcing mode, a socket lock race could occur between sctp_rcv() and
  sctp_accept(). A remote attacker could use this flaw to cause a denial of
  service. By default, SELinux runs in Enforcing mode on Red Hat Enterprise
  Linux 5. (CVE-2011-4348, Important)

  * The proc file system could allow a local, unprivileged user to obtain
  sensitive information or possibly cause integrity issues. (CVE-2011-1020,
  Moderate)

  * A missing validation flaw was found in the Linux kernel's m_stop()
  implementation. A local, unprivileged user could use this flaw to trigger a
  denial of service. (CVE-2011-3637, Moderate)

  * A flaw was found in the Linux kernel's Journaling Block Device (JBD).
  A local attacker could use this flaw to crash the system by mounting a
  specially-crafted ext3 or ext4 disk. (CVE-2011-4132, Moderate)

  * A flaw was found in the Linux kernel's encode_share_access()
  implementation. A local, unprivileged user could use this flaw to trigger a
  denial of service by creating a regular file on an NFSv4 (Network File
  System version 4) file system via mknod(). (CVE-2011-4324, Moderate)

  * A flaw was found in the Linux kernel's NFS implementation. A local,
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2011-4325, Moderate)

  * A missing boundary check was found in the Linux kernel's HFS file system
  implementation. A local attacker could use this flaw to cause a denial of
  service or escalate their privileges by mounting a specially-crafted disk.
  (CVE-2011-4330, Moderate)

  Red Hat would like to thank Kees Cook for reporting CVE-2011-1020, and
  Clement Lecigne for reporting CVE-2011-4330.

  This update also fixes several bugs and adds one enhancement. Documentation
  for these changes will be available shortly from the Technical Notes
  document linked to in the References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, and fix the bugs and add the enhancement
  noted in the Technical Notes. The system must be rebooted for this update
  to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
