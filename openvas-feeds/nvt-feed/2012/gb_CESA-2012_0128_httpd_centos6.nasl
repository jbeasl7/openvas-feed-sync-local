# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018433.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881089");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:05:13 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0031",
                "CVE-2012-0053", "CVE-2011-3368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2012:0128");
  script_name("CentOS Update for httpd CESA-2012:0128 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"httpd on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular web server.

  It was discovered that the fix for CVE-2011-3368 (released via
  RHSA-2011:1391) did not completely address the problem. An attacker could
  bypass the fix and make a reverse proxy connect to an arbitrary server not
  directly accessible to the attacker by sending an HTTP version 0.9 request,
  or by using a specially-crafted URI. (CVE-2011-3639, CVE-2011-4317)

  The httpd server included the full HTTP header line in the default error
  page generated when receiving an excessively long or malformed header.
  Malicious JavaScript running in the server's domain context could use this
  flaw to gain access to httpOnly cookies. (CVE-2012-0053)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way httpd performed substitutions in regular expressions. An
  attacker able to set certain httpd settings, such as a user permitted to
  override the httpd configuration for a specific directory using a
  '.htaccess' file, could use this flaw to crash the httpd child process or,
  possibly, execute arbitrary code with the privileges of the 'apache' user.
  (CVE-2011-3607)

  A flaw was found in the way httpd handled child process status information.
  A malicious program running with httpd child process privileges (such as a
  PHP or CGI script) could use this flaw to cause the parent httpd process to
  crash during httpd service shutdown. (CVE-2012-0031)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~15.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~15.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~15.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~15.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~15.el6.centos.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
