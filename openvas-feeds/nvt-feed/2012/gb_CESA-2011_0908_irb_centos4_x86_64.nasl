# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017672.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881337");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:26:31 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-4492", "CVE-2010-0541", "CVE-2011-0188", "CVE-2011-1005");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0908");
  script_name("CentOS Update for irb CESA-2011:0908 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irb'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"irb on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Ruby is an extensible, interpreted, object-oriented, scripting language. It
  has features to process text files and to do system management tasks.

  A flaw was found in the way large amounts of memory were allocated on
  64-bit systems when using the BigDecimal class. A context-dependent
  attacker could use this flaw to cause memory corruption, causing a Ruby
  application that uses the BigDecimal class to crash or, possibly, execute
  arbitrary code. This issue did not affect 32-bit systems. (CVE-2011-0188)

  It was found that WEBrick (the Ruby HTTP server toolkit) did not filter
  terminal escape sequences from its log files. A remote attacker could use
  specially-crafted HTTP requests to inject terminal escape sequences into
  the WEBrick log files. If a victim viewed the log files with a terminal
  emulator, it could result in control characters being executed with the
  privileges of that user. (CVE-2009-4492)

  A cross-site scripting (XSS) flaw was found in the way WEBrick displayed
  error pages. A remote attacker could use this flaw to perform a cross-site
  scripting attack against victims by tricking them into visiting a
  specially-crafted URL. (CVE-2010-0541)

  A flaw was found in the method for translating an exception message into a
  string in the Exception class. A remote attacker could use this flaw to
  bypass safe level 4 restrictions, allowing untrusted (tainted) code to
  modify arbitrary, trusted (untainted) strings, which safe level 4
  restrictions would otherwise prevent. (CVE-2011-1005)

  Red Hat would like to thank Drew Yao of Apple Product Security for
  reporting the CVE-2011-0188 and CVE-2010-0541 issues.

  All Ruby users should upgrade to these updated packages, which contain
  backported patches to resolve these issues.");
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

  if ((res = isrpmvuln(pkg:"irb", rpm:"irb~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.1~16.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
