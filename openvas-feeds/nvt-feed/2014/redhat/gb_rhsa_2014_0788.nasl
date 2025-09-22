# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871194");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-01 23:19:30 +0530 (Tue, 01 Jul 2014)");
  script_cve_id("CVE-2014-0240", "CVE-2014-0242");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:22:00 +0000 (Tue, 17 Dec 2019)");
  script_name("RedHat Update for mod_wsgi RHSA-2014:0788-01");


  script_tag(name:"affected", value:"mod_wsgi on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The mod_wsgi adapter is an Apache module that provides a WSGI-compliant
interface for hosting Python-based web applications within Apache.

It was found that mod_wsgi did not properly drop privileges if the call to
setuid() failed. If mod_wsgi was set up to allow unprivileged users to run
WSGI applications, a local user able to run a WSGI application could
possibly use this flaw to escalate their privileges on the system.
(CVE-2014-0240)

Note: mod_wsgi is not intended to provide privilege separation for WSGI
applications. Systems relying on mod_wsgi to limit or sandbox the
privileges of mod_wsgi applications should migrate to a different solution
with proper privilege separation.

It was discovered that mod_wsgi could leak memory of a hosted web
application via the 'Content-Type' header. A remote attacker could possibly
use this flaw to disclose limited portions of the web application's memory.
(CVE-2014-0242)

Red Hat would like to thank Graham Dumpleton for reporting these issues.
Upstream acknowledges Robert Kisteleki as the original reporter of
CVE-2014-0240, and Buck Golemon as the original reporter of CVE-2014-0242.

All mod_wsgi users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0788-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-June/msg00051.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_wsgi'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"mod_wsgi", rpm:"mod_wsgi~3.2~6.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_wsgi-debuginfo", rpm:"mod_wsgi-debuginfo~3.2~6.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
