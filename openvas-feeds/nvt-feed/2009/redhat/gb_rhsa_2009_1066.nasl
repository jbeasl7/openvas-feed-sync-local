# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64063");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1066");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1066.

A server-side code injection flaw was found in the SquirrelMail
map_yp_alias function. If SquirrelMail was configured to retrieve a
user's IMAP server address from a Network Information Service (NIS) server
via the map_yp_alias function, an unauthenticated, remote attacker using
a specially-crafted username could use this flaw to execute arbitrary code
with the privileges of the web server. (CVE-2009-1579)

Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. An
attacker could construct a carefully crafted URL, which once visited by an
unsuspecting user, could cause the user's web browser to execute malicious
script in the context of the visited SquirrelMail web page. (CVE-2009-1578)

It was discovered that SquirrelMail did not properly sanitize Cascading
Style Sheets (CSS) directives used in HTML mail. A remote attacker could
send a specially-crafted email that could place mail content above
SquirrelMail's controls, possibly allowing phishing and cross-site
scripting attacks. (CVE-2009-1581)

Users of squirrelmail should upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1066.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");
  script_xref(name:"URL", value:"http://www.squirrelmail.org/security/issue/2009-05-08");
  script_xref(name:"URL", value:"http://www.squirrelmail.org/security/issue/2009-05-10");
  script_xref(name:"URL", value:"http://www.squirrelmail.org/security/issue/2009-05-12");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~13.el3", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el4_8.5", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
