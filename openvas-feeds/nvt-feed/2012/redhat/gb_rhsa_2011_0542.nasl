# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870685");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:46:14 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-4251", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1023",
                "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1170",
                "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1495",
                "CVE-2011-1581");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 15:45:00 +0000 (Tue, 04 Aug 2020)");
  script_xref(name:"RHSA", value:"2011:0542-01");
  script_name("RedHat Update for Red Hat Enterprise Linux 6.1 kernel RHSA-2011:0542-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Red Hat Enterprise Linux 6.1 kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"Red Hat Enterprise Linux 6.1 kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * Multiple buffer overflow flaws were found in the Linux kernel's
  Management Module Support for Message Passing Technology (MPT) based
  controllers. A local, unprivileged user could use these flaws to cause a
  denial of service, an information leak, or escalate their privileges.
  (CVE-2011-1494, CVE-2011-1495, Important)

  * A flaw was found in the Linux kernel's Ethernet bonding driver
  implementation. Packets coming in from network devices that have more
  than 16 receive queues to a bonding interface could cause a denial of
  service. (CVE-2011-1581, Important)

  * A flaw was found in the Linux kernel's networking subsystem. If the
  number of packets received exceeded the receiver's buffer limit, they were
  queued in a backlog, consuming memory, instead of being discarded. A remote
  attacker could abuse this flaw to cause a denial of service (out-of-memory
  condition). (CVE-2010-4251, Moderate)

  * A flaw was found in the Linux kernel's Transparent Huge Pages (THP)
  implementation. A local, unprivileged user could abuse this flaw to allow
  the user stack (when it is using huge pages) to grow and cause a denial of
  service. (CVE-2011-0999, Moderate)

  * A flaw was found in the transmit methods (xmit) for the loopback and
  InfiniBand transports in the Linux kernel's Reliable Datagram Sockets (RDS)
  implementation. A local, unprivileged user could use this flaw to cause a
  denial of service. (CVE-2011-1023, Moderate)

  * A flaw in the Linux kernel's Event Poll (epoll) implementation could
  allow a local, unprivileged user to cause a denial of service.
  (CVE-2011-1082, Moderate)

  * An inconsistency was found in the interaction between the Linux kernel's
  method for allocating NFSv4 (Network File System version 4) ACL data and
  the method by which it was freed. This inconsistency led to a kernel panic
  which could be triggered by a local, unprivileged user with files owned by
  said user on an NFSv4 share. (CVE-2011-1090, Moderate)

  * A missing validation check was found in the Linux kernel's
  mac_partition() implementation, used for supporting file systems created
  on Mac OS operating systems. A local attacker could use this flaw to cause
  a denial of service by mounting a disk that contains specially-crafted
  partitions. (CVE-2011-1010, Low)

  * A buffer  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~131.0.15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
