# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882004");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-10 06:19:51 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-0181", "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2706",
                "CVE-2014-3534", "CVE-2014-4667");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2014:1023 centos7");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * It was found that Linux kernel's ptrace subsystem did not properly
sanitize the address-space-control bits when the program-status word (PSW)
was being set. On IBM S/390 systems, a local, unprivileged user could use
this flaw to set address-space-control bits to the kernel space, and thus
gain read and write access to kernel memory. (CVE-2014-3534, Important)

  * It was found that the permission checks performed by the Linux kernel
when a netlink message was received were not sufficient. A local,
unprivileged user could potentially bypass these restrictions by passing a
netlink socket as stdout or stderr to a more privileged process and
altering the output of this process. (CVE-2014-0181, Moderate)

  * It was found that a remote attacker could use a race condition flaw in
the ath_tx_aggr_sleep() function to crash the system by creating large
network traffic on the system's Atheros 9k wireless network adapter.
(CVE-2014-2672, Moderate)

  * A flaw was found in the way the Linux kernel performed forking inside of
a transaction. A local, unprivileged user on a PowerPC system that supports
transactional memory could use this flaw to crash the system.
(CVE-2014-2673, Moderate)

  * A race condition flaw was found in the way the Linux kernel's mac80211
subsystem implementation handled synchronization between TX and STA wake-up
code paths. A remote attacker could use this flaw to crash the system.
(CVE-2014-2706, Moderate)

  * An integer underflow flaw was found in the way the Linux kernel's Stream
Control Transmission Protocol (SCTP) implementation processed certain
COOKIE_ECHO packets. By sending a specially crafted SCTP packet, a remote
attacker could use this flaw to prevent legitimate connections to a
particular SCTP server socket to be made. (CVE-2014-4667, Moderate)

Red Hat would like to thank Martin Schwidefsky of IBM for reporting
CVE-2014-3534, Andy Lutomirski for reporting CVE-2014-0181, and Gopal Reddy
Kodudula of Nokia Siemens Networks for reporting CVE-2014-4667.

This update also fixes the following bugs:

  * Due to a NULL pointer dereference bug in the IPIP and SIT tunneling code,
a kernel panic could be triggered when using IPIP or SIT tunnels with
IPsec. This update restructures the related code to avoid a NULL pointer
dereference and the kernel no longer panics when using IPIP or SIT tunnels
with IPsec. (BZ#1114957)

  * Previously, an IBM POWER8 system could terminate unexpectedly when the
kernel received an IRQ while handling a transactional memory re-checkpoint
critical section. This update ensures that  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1023");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020475.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.6.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
