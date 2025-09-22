# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881739");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-31 09:51:21 +0530 (Fri, 31 May 2013)");
  script_cve_id("CVE-2013-1912");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for haproxy CESA-2013:0868 centos6");

  script_xref(name:"CESA", value:"2013:0868");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019749.html");
  script_xref(name:"URL", value:"https://access.redhat.com/support/offerings/techpreview");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"haproxy on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"HAProxy provides high availability, load balancing, and proxying for TCP
  and HTTP-based applications.

  A buffer overflow flaw was found in the way HAProxy handled pipelined HTTP
  requests. A remote attacker could send pipelined HTTP requests that would
  cause HAProxy to crash or, potentially, execute arbitrary code with the
  privileges of the user running HAProxy. This issue only affected systems
  using all of the following combined configuration options: HTTP keep alive
  enabled, HTTP keywords in TCP inspection rules, and request appending
  rules. (CVE-2013-1912)

  Red Hat would like to thank Willy Tarreau of HAProxy upstream for reporting
  this issue. Upstream acknowledges Yves Lafon from the W3C as the original
  reporter.

  HAProxy is released as a Technology Preview in Red Hat Enterprise Linux 6.
  More information about Red Hat Technology Previews is available at the linked reference.

  All users of haproxy are advised to upgrade to this updated package, which
  contains a backported patch to correct this issue.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.4.22~4.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
