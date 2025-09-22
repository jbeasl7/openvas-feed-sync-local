# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-February/018422.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881223");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-30 16:50:51 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555",
                "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:56:01 +0000 (Thu, 08 Feb 2024)");
  script_xref(name:"CESA", value:"2012:0103");
  script_name("CentOS Update for squirrelmail CESA-2012:0103 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"squirrelmail on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"SquirrelMail is a standards-based webmail package written in PHP.

  A cross-site scripting (XSS) flaw was found in the way SquirrelMail
  performed the sanitization of HTML style tag content. A remote attacker
  could use this flaw to send a specially-crafted Multipurpose Internet Mail
  Extensions (MIME) message that, when opened by a victim, would lead to
  arbitrary web script execution in the context of their SquirrelMail
  session. (CVE-2011-2023)

  Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. A
  remote attacker could possibly use these flaws to execute arbitrary web
  script in the context of a victim's SquirrelMail session. (CVE-2010-4555)

  An input sanitization flaw was found in the way SquirrelMail handled the
  content of various HTML input fields. A remote attacker could use this
  flaw to alter user preference values via a newline character contained in
  the input for these fields. (CVE-2011-2752)

  It was found that the SquirrelMail Empty Trash and Index Order pages did
  not protect against Cross-Site Request Forgery (CSRF) attacks. If a remote
  attacker could trick a user, who was logged into SquirrelMail, into
  visiting a specially-crafted URL, the attacker could empty the victim's
  trash folder or alter the ordering of the columns on the message index
  page. (CVE-2011-2753)

  SquirrelMail was allowed to be loaded into an HTML sub-frame, allowing a
  remote attacker to perform a clickjacking attack against logged in users
  and possibly gain access to sensitive user data. With this update, the
  SquirrelMail main frame can only be loaded into the top most browser frame.
  (CVE-2010-4554)

  A flaw was found in the way SquirrelMail handled failed log in attempts. A
  user preference file was created when attempting to log in with a password
  containing an 8-bit character, even if the username was not valid. A
  remote attacker could use this flaw to eventually consume all hard disk
  space on the target SquirrelMail server. (CVE-2010-2813)

  A flaw was found in the SquirrelMail Mail Fetch plug-in. If an
  administrator enabled this plug-in, a SquirrelMail user could use this flaw
  to port scan the local network the server was on. (CVE-2010-1637)

  Users of SquirrelMail should upgrade to this updated package, which
  contains backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~18.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
