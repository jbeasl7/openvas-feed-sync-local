# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019636.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881673");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-12 10:02:10 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2013-0787");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2013:0614");
  script_name("CentOS Update for xulrunner CESA-2013:0614 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xulrunner on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"XULRunner provides the XUL Runtime environment for applications using the
  Gecko layout engine.

  A flaw was found in the way XULRunner handled malformed web content. A web
  page containing malicious content could cause an application linked against
  XULRunner (such as Mozilla Firefox) to crash or execute arbitrary code with
  the privileges of the user running the application. (CVE-2013-0787)

  Red Hat would like to thank the Mozilla project for reporting this issue.
  Upstream acknowledges VUPEN Security via the TippingPoint Zero Day
  Initiative project as the original reporter.

  For technical details regarding this flaw, refer to the Mozilla security
  advisories. You can find a link to the Mozilla advisories in the References
  section of this erratum.

  All XULRunner users should upgrade to these updated packages, which correct
  this issue. After installing the update, applications using XULRunner must
  be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~2.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~2.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
