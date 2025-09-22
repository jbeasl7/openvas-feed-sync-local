# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00053.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27409");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56753");
  script_oid("1.3.6.1.4.1.25623.1.0.870908");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:00:33 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2008-0455", "CVE-2012-2687", "CVE-2012-4557");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2013:0512-02");
  script_name("RedHat Update for httpd RHSA-2013:0512-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"httpd on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The httpd packages contain the Apache HTTP Server (httpd), which is the
  namesake project of The Apache Software Foundation.

  An input sanitization flaw was found in the mod_negotiation Apache HTTP
  Server module. A remote attacker able to upload or create files with
  arbitrary names in a directory that has the MultiViews options enabled,
  could use this flaw to conduct cross-site scripting attacks against users
  visiting the site. (CVE-2008-0455, CVE-2012-2687)

  It was discovered that mod_proxy_ajp, when used in configurations with
  mod_proxy in load balancer mode, would mark a back-end server as failed
  when request processing timed out, even when a previous AJP (Apache JServ
  Protocol) CPing request was responded to by the back-end. A remote
  attacker able to make a back-end use an excessive amount of time to
  process a request could cause mod_proxy to not send requests to back-end
  AJP servers for the retry timeout period or until all back-end servers
  were marked as failed. (CVE-2012-4557)

  These updated httpd packages include numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 6.4 Technical Notes, linked
  to in the References, for information on the most significant of these
  changes.

  All users of httpd are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues and add these
  enhancements. After installing the updated packages, the httpd daemon will
  be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~26.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
