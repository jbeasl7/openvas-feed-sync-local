# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882694");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-14 06:30:31 +0200 (Fri, 14 Apr 2017)");
  script_cve_id("CVE-2016-8650", "CVE-2016-9793", "CVE-2017-2618", "CVE-2017-2636");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:05:00 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:0933 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

These updated kernel packages include several security issues and numerous
bug fixes. Space precludes documenting all of these bug fixes in this
advisory. To see the complete list of bug fixes, users are directed to the
references Knowledge Article.

Security Fix(es):

  * A race condition flaw was found in the N_HLDC Linux kernel driver when
accessing n_hdlc.tbuf list that can lead to double free. A local,
unprivileged user able to set the HDLC line discipline on the tty device
could use this flaw to increase their privileges on the system.
(CVE-2017-2636, Important)

  * A flaw was found in the Linux kernel key management subsystem in which a
local attacker could crash the kernel or corrupt the stack and additional
memory (denial of service) by supplying a specially crafted RSA key. This
flaw panics the machine during the verification of the RSA key.
(CVE-2016-8650, Moderate)

  * A flaw was found in the Linux kernel's implementation of setsockopt for
the SO_{SND RCV}BUFFORCE setsockopt() system call. Users with non-namespace
CAP_NET_ADMIN are able to trigger this call and create a situation in which
the sockets sendbuff data size could be negative. This could adversely
affect memory allocations and create situations where the system could
crash or cause memory corruption. (CVE-2016-9793, Moderate)

  * A flaw was found in the Linux kernel's handling of clearing SELinux
attributes on /proc/pid/attr files. An empty (null) write to this file can
crash the system by causing the system to attempt to access unmapped kernel
memory. (CVE-2017-2618, Moderate)

Red Hat would like to thank Alexander Popov for reporting CVE-2017-2636 and
Ralf Spenneberg for reporting CVE-2016-8650. The CVE-2017-2618 issue was
discovered by Paul Moore (Red Hat Engineering).");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0933");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-April/022385.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/2986951");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~514.16.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
