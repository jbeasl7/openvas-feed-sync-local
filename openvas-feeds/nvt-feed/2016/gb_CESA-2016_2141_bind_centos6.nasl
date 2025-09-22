# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882588");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-08 15:52:56 +0530 (Tue, 08 Nov 2016)");
  script_cve_id("CVE-2016-8864");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 17:44:00 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for bind CESA-2016:2141 centos6");
  script_tag(name:"summary", value:"Check the version of bind");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is
an implementation of the Domain Name System (DNS) protocols. BIND includes a DNS
server (named)  a resolver library (routines for applications to use when
interfacing with DNS)  and tools for verifying that the DNS server is operating
correctly.

Security Fix(es):

  * A denial of service flaw was found in the way BIND handled responses
containing a DNAME answer. A remote attacker could use this flaw to make
named exit unexpectedly with an assertion failure via a specially crafted
DNS response. (CVE-2016-8864)

Red Hat would like to thank ISC for reporting this issue. Upstream
acknowledges Tony Finch (University of Cambridge) and Marco Davids (SIDN
Labs) as the original reporters.");
  script_tag(name:"affected", value:"bind on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:2141");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-November/022136.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.47.rc1.el6_8.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
