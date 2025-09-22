# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881772");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-01 18:43:37 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2013-2175");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for haproxy CESA-2013:1120 centos6");

  script_tag(name:"affected", value:"haproxy on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"HAProxy provides high availability, load balancing, and proxying for TCP
and HTTP-based applications.

A flaw was found in the way HAProxy handled requests when the proxy's
configuration ('/etc/haproxy/haproxy.cfg') had certain rules that use the
hdr_ip criterion. A remote attacker could use this flaw to crash HAProxy
instances that use the affected configuration. (CVE-2013-2175)

Red Hat would like to thank HAProxy upstream for reporting this issue.
Upstream acknowledges David Torgerson as the original reporter.

HAProxy is released as a Technology Preview in Red Hat Enterprise Linux 6.
More information about Red Hat Technology Previews is available at the linked references.

All users of haproxy are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1120");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-July/019884.html");
  script_xref(name:"URL", value:"https://access.redhat.com/support/offerings/techpreview/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.4.22~5.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
