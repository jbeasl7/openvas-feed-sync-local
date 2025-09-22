# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-January/015546.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880721");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2009:0010");
  script_cve_id("CVE-2008-2379", "CVE-2008-3663");
  script_name("CentOS Update for squirrelmail CESA-2009:0010 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"squirrelmail on CentOS 5");
  script_tag(name:"insight", value:"SquirrelMail is an easy-to-configure, standards-based, webmail package
  written in PHP. It includes built-in PHP support for the IMAP and SMTP
  protocols, and pure HTML 4.0 page-rendering (with no JavaScript required)
  for maximum browser-compatibility, strong MIME support, address books, and
  folder manipulation.

  Ivan Markovic discovered a cross-site scripting (XSS) flaw in SquirrelMail
  caused by insufficient HTML mail sanitization. A remote attacker could send
  a specially-crafted HTML mail or attachment that could cause a user's Web
  browser to execute a malicious script in the context of the SquirrelMail
  session when that email or attachment was opened by the user.
  (CVE-2008-2379)

  It was discovered that SquirrelMail allowed cookies over insecure
  connections (ie did not restrict cookies to HTTPS connections). An attacker
  who controlled the communication channel between a user and the
  SquirrelMail server, or who was able to sniff the user's network
  communication, could use this flaw to obtain the user's session cookie, if
  a user made an HTTP request to the server. (CVE-2008-3663)

  Note: After applying this update, all session cookies set for SquirrelMail
  sessions started over HTTPS connections will have the 'secure' flag set.
  That is, browsers will only send such cookies over an HTTPS connection. If
  needed, you can revert to the previous behavior by setting the
  configuration option '$only_secure_cookies' to 'false'
  in SquirrelMail's /etc/squirrelmail/config.php configuration file.

  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el5.centos.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
