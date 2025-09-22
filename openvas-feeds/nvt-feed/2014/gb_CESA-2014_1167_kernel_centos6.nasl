# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882012");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:23 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-0205", "CVE-2014-3535", "CVE-2014-3917", "CVE-2014-4667");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2014:1167 centos6");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * A flaw was found in the way the Linux kernel's futex subsystem handled
reference counting when requeuing futexes during futex_wait(). A local,
unprivileged user could use this flaw to zero out the reference counter of
an inode or an mm struct that backs up the memory area of the futex, which
could lead to a use-after-free flaw, resulting in a system crash or,
potentially, privilege escalation. (CVE-2014-0205, Important)

  * A NULL pointer dereference flaw was found in the way the Linux kernel's
networking implementation handled logging while processing certain invalid
packets coming in via a VxLAN interface. A remote attacker could use this
flaw to crash the system by sending a specially crafted packet to such an
interface. (CVE-2014-3535, Important)

  * An out-of-bounds memory access flaw was found in the Linux kernel's
system call auditing implementation. On a system with existing audit rules
defined, a local, unprivileged user could use this flaw to leak kernel
memory to user space or, potentially, crash the system. (CVE-2014-3917,
Moderate)

  * An integer underflow flaw was found in the way the Linux kernel's Stream
Control Transmission Protocol (SCTP) implementation processed certain
COOKIE_ECHO packets. By sending a specially crafted SCTP packet, a remote
attacker could use this flaw to prevent legitimate connections to a
particular SCTP server socket to be made. (CVE-2014-4667, Moderate)

Red Hat would like to thank Gopal Reddy Kodudula of Nokia Siemens Networks
for reporting CVE-2014-4667. The security impact of the CVE-2014-0205 issue
was discovered by Mateusz Guzik of Red Hat.

This update also fixes several bugs. Documentation for these changes will
be available shortly from the Technical Notes document linked to in the
References section.

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1167");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020548.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.29.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
