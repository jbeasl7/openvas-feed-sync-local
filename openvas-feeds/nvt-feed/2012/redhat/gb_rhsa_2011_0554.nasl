# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870597");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:31:24 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3493", "CVE-2011-1015", "CVE-2011-1521");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_xref(name:"RHSA", value:"2011:0554-01");
  script_name("RedHat Update for python RHSA-2011:0554-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"python on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Python is an interpreted, interactive, object-oriented programming
  language.

  A flaw was found in the Python urllib and urllib2 libraries where they
  would not differentiate between different target URLs when handling
  automatic redirects. This caused Python applications using these modules to
  follow any new URL that they understood, including the 'file://' URL type.
  This could allow a remote server to force a local Python application to
  read a local file instead of the remote one, possibly exposing local files
  that were not meant to be exposed. (CVE-2011-1521)

  A race condition was found in the way the Python smtpd module handled new
  connections. A remote user could use this flaw to cause a Python script
  using the smtpd module to terminate. (CVE-2010-3493)

  An information disclosure flaw was found in the way the Python
  CGIHTTPServer module processed certain HTTP GET requests. A remote attacker
  could use a specially-crafted request to obtain the CGI script's source
  code. (CVE-2011-1015)

  This erratum also upgrades Python to upstream version 2.6.6, and includes a
  number of bug fixes and enhancements. Documentation for these bug fixes
  and enhancements is available from the Technical Notes document, linked to
  in the References section.

  All users of Python are advised to upgrade to these updated packages, which
  correct these issues, and fix the bugs and add the enhancements noted in
  the Technical Notes.");
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

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~20.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.6.6~20.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~20.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~20.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~20.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.6.6~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
