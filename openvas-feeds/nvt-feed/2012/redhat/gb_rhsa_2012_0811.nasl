# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870762");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-22 10:25:59 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2010-3294");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name:"RHSA", value:"2012:0811-04");
  script_name("RedHat Update for php-pecl-apc RHSA-2012:0811-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-pecl-apc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"php-pecl-apc on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The php-pecl-apc packages contain APC (Alternative PHP Cache), the
  framework for caching and optimization of intermediate PHP code.

  A cross-site scripting (XSS) flaw was found in the 'apc.php' script, which
  provides a detailed analysis of the internal workings of APC and is shipped
  as part of the APC extension documentation. A remote attacker could
  possibly use this flaw to conduct a cross-site scripting attack.
  (CVE-2010-3294)

  Note: The administrative script is not deployed upon package installation.
  It must manually be copied to the web root (the default is
  '/var/www/html/', for example).

  In addition, the php-pecl-apc packages have been upgraded to upstream
  version 3.1.9, which provides a number of bug fixes and enhancements over
  the previous version. (BZ#662655)

  All users of php-pecl-apc are advised to upgrade to these updated packages,
  which fix these issues and add these enhancements. If the 'apc.php' script
  was previously deployed in the web root, it must manually be re-deployed to
  replace the vulnerable version to resolve this issue.");
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

  if ((res = isrpmvuln(pkg:"php-pecl-apc", rpm:"php-pecl-apc~3.1.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pecl-apc-debuginfo", rpm:"php-pecl-apc-debuginfo~3.1.9~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
