# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018730.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881174");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-30 16:33:18 +0530 (Mon, 30 Jul 2012)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-2950", "CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0781",
                "CVE-2012-0789", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2336",
                "CVE-2012-2386", "CVE-2012-1823");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"CESA", value:"2012:1046");
  script_name("CentOS Update for php CESA-2012:1046 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"php on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  It was discovered that the PHP XSL extension did not restrict the file
  writing capability of libxslt. A remote attacker could use this flaw to
  create or overwrite an arbitrary file that is writable by the user running
  PHP, if a PHP script processed untrusted eXtensible Style Sheet Language
  Transformations (XSLT) content. (CVE-2012-0057)

  Note: This update disables file writing by default. A new PHP configuration
  directive, 'xsl.security_prefs', can be used to enable file writing in
  XSLT.

  A flaw was found in the way PHP validated file names in file upload
  requests. A remote attacker could possibly use this flaw to bypass the
  sanitization of the uploaded file names, and cause a PHP script to store
  the uploaded file in an unexpected directory, by using a directory
  traversal attack. (CVE-2012-1172)

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the PHP phar extension processed certain fields of
  tar archive files. A remote attacker could provide a specially-crafted tar
  archive file that, when processed by a PHP application using the phar
  extension, could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running PHP. (CVE-2012-2386)

  A format string flaw was found in the way the PHP phar extension processed
  certain PHAR files. A remote attacker could provide a specially-crafted
  PHAR file, which once processed in a PHP application using the phar
  extension, could lead to information disclosure and possibly arbitrary code
  execution via a crafted phar:// URI. (CVE-2010-2950)

  A flaw was found in the DES algorithm implementation in the crypt()
  password hashing function in PHP. If the password string to be hashed
  contained certain characters, the remainder of the string was ignored when
  calculating the hash, significantly reducing the password strength.
  (CVE-2012-2143)

  Note: With this update, passwords are no longer truncated when performing
  DES hashing. Therefore, new hashes of the affected passwords will not match
  stored hashes generated using vulnerable PHP versions, and will need to be
  updated.

  It was discovered that the fix for CVE-2012-1823, released via
  RHSA-2012:0546, did not properly filter all php-cgi command line arguments.
  A specially-crafted request to a PHP script could cause the PHP interpreter
  to execute the script in a loop, or output usage information that triggers
  an Internal Server Error. (CVE-2012-2 ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-bcmath", rpm:"php-bcmath~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-dba", rpm:"php-dba~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-embedded", rpm:"php-embedded~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-enchant", rpm:"php-enchant~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-intl", rpm:"php-intl~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pspell", rpm:"php-pspell~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-tidy", rpm:"php-tidy~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-zts", rpm:"php-zts~5.3.3~14.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
