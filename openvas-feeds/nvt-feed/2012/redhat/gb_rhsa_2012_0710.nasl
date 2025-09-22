# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870748");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-08 10:11:30 +0530 (Fri, 08 Jun 2012)");
  script_cve_id("CVE-2011-3101", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1939",
                "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945",
                "CVE-2012-1946", "CVE-2012-1947");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:0710-01");
  script_name("RedHat Update for firefox RHSA-2012:0710-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-3101, CVE-2012-1937, CVE-2012-1938, CVE-2012-1939,
  CVE-2012-1940, CVE-2012-1941, CVE-2012-1946, CVE-2012-1947)

  Note: CVE-2011-3101 only affected users of certain NVIDIA display drivers
  with graphics cards that have hardware acceleration enabled.

  It was found that the Content Security Policy (CSP) implementation in
  Firefox no longer blocked Firefox inline event handlers. A remote attacker
  could use this flaw to possibly bypass a web application's intended
  restrictions, if that application relied on CSP to protect against flaws
  such as cross-site scripting (XSS). (CVE-2012-1944)

  If a web server hosted HTML files that are stored on a Microsoft Windows
  share, or a Samba share, loading such files with Firefox could result in
  Windows shortcut files (.lnk) in the same share also being loaded. An
  attacker could use this flaw to view the contents of local files and
  directories on the victim's system. This issue also affected users opening
  HTML files from Microsoft Windows shares, or Samba shares, that are mounted
  on their systems. (CVE-2012-1945)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.5 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Ken Russell of Google as the original reporter of
  CVE-2011-3101, Igor Bukanov, Olli Pettay, Boris Zbarsky, and Jesse Ruderman
  as the original reporters of CVE-2012-1937, Jesse Ruderman, Igor Bukanov,
  Bill McCloskey, Christian Holler, Andrew McCreight, and Brian Bondy as the
  original reporters of CVE-2012-1938, Christian Holler as the original
  reporter of CVE-2012-1939, security researcher Abhishek Arya of Google as
  the original reporter of CVE-2012-1940, CVE-2012-1941, and CVE-2012-1947,
  security researcher Arthur Gerkis as the original reporter of
  CVE-2012-1946, security researcher Adam Barth as the original reporter of
  CVE-2012-1944, and security researcher Paul Stone as the orig ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.5~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~10.0.5~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.5~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~10.0.5~1.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.5~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~10.0.5~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.5~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~10.0.5~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.5~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
