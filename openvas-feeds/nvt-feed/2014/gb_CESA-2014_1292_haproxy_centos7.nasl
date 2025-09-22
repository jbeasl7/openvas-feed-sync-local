# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882029");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-25 05:58:35 +0200 (Thu, 25 Sep 2014)");
  script_cve_id("CVE-2014-6269");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for haproxy CESA-2014:1292 centos7");
  script_tag(name:"insight", value:"HAProxy provides high availability,
load balancing, and proxying for TCP and HTTP-based applications.

A buffer overflow flaw was discovered in the way HAProxy handled, under
very specific conditions, data uploaded from a client. A remote attacker
could possibly use this flaw to crash HAProxy. (CVE-2014-6269)

All haproxy users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"affected", value:"haproxy on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1292");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020584.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
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

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.5.2~3.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
