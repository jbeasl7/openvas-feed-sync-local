# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017666.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881351");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:34:30 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-2697");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:1109");
  script_name("CentOS Update for foomatic CESA-2011:1109 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'foomatic'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"foomatic on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Foomatic is a comprehensive, spooler-independent database of printers,
  printer drivers, and driver descriptions. The package also includes
  spooler-independent command line interfaces to manipulate queues and to
  print files and manipulate print jobs. foomatic-rip is a print filter
  written in Perl.

  An input sanitization flaw was found in the foomatic-rip print filter. An
  attacker could submit a print job with the username, title, or job options
  set to appear as a command line option that caused the filter to use a
  specified PostScript printer description (PPD) file, rather than the
  administrator-set one. This could lead to arbitrary code execution with the
  privileges of the 'lp' user. (CVE-2011-2697)

  All foomatic users should upgrade to this updated package, which contains
  a backported patch to resolve this issue.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"foomatic", rpm:"foomatic~3.0.2~3.2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
