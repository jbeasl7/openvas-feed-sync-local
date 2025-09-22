# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-October/018911.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881511");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-05 09:43:26 +0530 (Fri, 05 Oct 2012)");
  script_cve_id("CVE-2012-2319", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3510", "CVE-2009-4020");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2012:1323");
  script_name("CentOS Update for kernel CESA-2012:1323 centos5");

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

  * A flaw was found in the way socket buffers (skb) requiring TSO (TCP
  segment offloading) were handled by the sfc driver. If the skb did not fit
  within the minimum-size of the transmission queue, the network card could
  repeatedly reset itself. A remote attacker could use this flaw to cause a
  denial of service. (CVE-2012-3412, Important)

  * A use-after-free flaw was found in the xacct_add_tsk() function in the
  Linux kernel's taskstats subsystem. A local, unprivileged user could use
  this flaw to cause an information leak or a denial of service.
  (CVE-2012-3510, Moderate)

  * A buffer overflow flaw was found in the hfs_bnode_read() function in the
  HFS Plus (HFS+) file system implementation in the Linux kernel. A local
  user able to mount a specially-crafted HFS+ file system image could use
  this flaw to cause a denial of service or escalate their privileges.
  (CVE-2012-2319, Low)

  * A flaw was found in the way the msg_namelen variable in the rds_recvmsg()
  function of the Linux kernel's Reliable Datagram Sockets (RDS) protocol
  implementation was initialized. A local, unprivileged user could use this
  flaw to leak kernel stack memory to user-space. (CVE-2012-3430, Low)

  Red Hat would like to thank Ben Hutchings of Solarflare (tm) for reporting
  CVE-2012-3412, and Alexander Peslyak for reporting CVE-2012-3510. The
  CVE-2012-3430 issue was discovered by the Red Hat InfiniBand team.

  This update also fixes the following bugs:

  * The cpuid_whitelist() function, masking the Enhanced Intel SpeedStep
  (EST) flag from all guests, prevented the 'cpuspeed' service from working
  in the privileged Xen domain (dom0). CPU scaling was therefore not
  possible. With this update, cpuid_whitelist() is aware whether the domain
  executing CPUID is privileged or not, and enables the EST flag for dom0.
  (BZ#846125)

  * If a delayed-allocation write was performed before quota was enabled,
  the kernel displayed the following warning message:

      WARNING: at fs/quota/dquot.c:988 dquot_claim_space+0x77/0x112()

  This was because information about the delayed allocation was not recorded
  in the quota structure. With this update, writes prior to enabling quota
  are properly accounted for, and the message is not displayed. (BZ#847326)

  * In Red Hat Enterprise Linux 5.9, the DSCP (Differentiated Services Code
  Point) netfilter module now supports mangling of the DSCP field.
  (BZ#847327)

  * Some subsys ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.16.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
