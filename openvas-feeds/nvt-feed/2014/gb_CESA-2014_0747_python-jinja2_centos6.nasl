# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881951");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-17 10:03:42 +0530 (Tue, 17 Jun 2014)");
  script_cve_id("CVE-2014-1402");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for python-jinja2 CESA-2014:0747 centos6");

  script_tag(name:"affected", value:"python-jinja2 on CentOS 6");
  script_tag(name:"insight", value:"Jinja2 is a template engine written in pure Python. It
provides a Django-inspired, non-XML syntax but supports inline expressions and
an optional sandboxed environment.

It was discovered that Jinja2 did not properly handle bytecode cache files
stored in the system's temporary directory. A local attacker could use this
flaw to alter the output of an application using Jinja2 and
FileSystemBytecodeCache, and potentially execute arbitrary code with the
privileges of that application. (CVE-2014-1402)

All python-jinja2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update to
take effect, all applications using python-jinja2 must be restarted.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0747");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020367.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-jinja2'
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

  if ((res = isrpmvuln(pkg:"python-jinja2", rpm:"python-jinja2~2.2.1~2.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
