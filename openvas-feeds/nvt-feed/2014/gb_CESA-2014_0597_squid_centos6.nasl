# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881945");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-09 12:31:54 +0530 (Mon, 09 Jun 2014)");
  script_cve_id("CVE-2014-0128");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for squid CESA-2014:0597 centos6");

  script_tag(name:"affected", value:"squid on CentOS 6");
  script_tag(name:"insight", value:"Squid is a high-performance proxy caching server for web
clients, supporting FTP, Gopher, and HTTP data objects.

A denial of service flaw was found in the way Squid processed certain HTTPS
requests when the SSL Bump feature was enabled. A remote attacker could
send specially crafted requests that could cause Squid to crash.
(CVE-2014-0128)

Red Hat would like to thank the Squid project for reporting this issue.
Upstream acknowledges Mathias Fischer and Fabian Hugelshofer from Open
Systems AG as the original reporters.

All squid users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, the squid service will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0597");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020340.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.1.10~20.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
