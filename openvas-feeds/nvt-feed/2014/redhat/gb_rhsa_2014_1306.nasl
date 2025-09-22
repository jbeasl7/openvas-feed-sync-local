# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871250");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-09-26 06:07:13 +0200 (Fri, 26 Sep 2014)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-7169", "CVE-2014-6271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");
  script_name("RedHat Update for bash RHSA-2014:1306-01");
  script_tag(name:"insight", value:"The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

It was found that the fix for CVE-2014-6271 was incomplete, and Bash still
allowed certain characters to be injected into other environments via
specially crafted environment variables. An attacker could potentially use
this flaw to override or bypass environment restrictions to execute shell
commands. Certain services and applications allow remote unauthenticated
attackers to provide environment variables, allowing them to exploit this
issue. (CVE-2014-7169)

Applications which directly create bash functions as environment variables
need to be made aware of changes to the way names are handled by this
update. For more information see the referenced Knowledgebase article.

Note: Docker users are advised to use 'yum update' within their containers,
and to commit the resulting changes.

For additional information on CVE-2014-6271 and CVE-2014-7169, refer to the
aforementioned Knowledgebase article.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  script_tag(name:"affected", value:"bash on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"RHSA", value:"2014:1306-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-September/msg00053.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6|5)");

  script_xref(name:"URL", value:"https://access.redhat.com/articles/1200223");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~4.2.45~5.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.2.45~5.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~4.1.2~15.el6_5.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.1.2~15.el6_5.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~3.2~33.el5_11.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~3.2~33.el5_11.4", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
