# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53225");
  script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521", "CVE-2004-0639");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-535");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-535");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-535");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squirrelmail' package(s) announced via the DSA-535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Four vulnerabilities were discovered in squirrelmail:

CAN-2004-0519

Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail 1.4.2 allow remote attackers to execute arbitrary script as other users and possibly steal authentication information via multiple attack vectors, including the mailbox parameter in compose.php.

CAN-2004-0520

Cross-site scripting (XSS) vulnerability in mime.php for SquirrelMail before 1.4.3 allows remote attackers to insert arbitrary HTML and script via the content-type mail header, as demonstrated using read_body.php.

CAN-2004-0521

SQL injection vulnerability in SquirrelMail before 1.4.3 RC1 allows remote attackers to execute unauthorized SQL statements, with unknown impact, probably via abook_database.php.

CAN-2004-0639

Multiple cross-site scripting (XSS) vulnerabilities in Squirrelmail 1.2.10 and earlier allow remote attackers to inject arbitrary HTML or script via (1) the $mailer variable in read_body.php, (2) the $senderNames_part variable in mailbox_display.php, and possibly other vectors including (3) the $event_title variable or (4) the $event_text variable.

For the current stable distribution (woody), these problems have been fixed in version 1:1.2.6-1.4.

For the unstable distribution (sid), these problems have been fixed in 2:1.4.3a-0.1 and earlier versions.

We recommend that you update your squirrelmail package.");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"squirrelmail", ver:"1:1.2.6-1.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
