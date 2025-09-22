# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64808");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
  script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("RedHat Security Advisory RHSA-2009:1427");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1427.

Fetchmail is a remote mail retrieval and forwarding utility intended for
use over on-demand TCP/IP links, such as SLIP and PPP connections.

It was discovered that fetchmail is affected by the previously published
null prefix attack, caused by incorrect handling of NULL characters in
X.509 certificates. If an attacker is able to get a carefully-crafted
certificate signed by a trusted Certificate Authority, the attacker could
use the certificate during a man-in-the-middle attack and potentially
confuse fetchmail into accepting it by mistake. (CVE-2009-2666)

A flaw was found in the way fetchmail handles rejections from a remote SMTP
server when sending warning mail to the postmaster. If fetchmail sent a
warning mail to the postmaster of an SMTP server and that SMTP server
rejected it, fetchmail could crash. (CVE-2007-4565)

A flaw was found in fetchmail. When fetchmail is run in double verbose
mode (-v -v), it could crash upon receiving certain, malformed mail
messages with long headers. A remote attacker could use this flaw to cause
a denial of service if fetchmail was also running in daemon mode (-d).
(CVE-2008-2711)

Note: when using SSL-enabled services, it is recommended that the fetchmail

  - -sslcertck option be used to enforce strict SSL certificate checking.

All fetchmail users should upgrade to this updated package, which contains
backported patches to correct these issues. If fetchmail is running in
daemon mode, it must be restarted for this update to take effect (use the
fetchmail --quit command to stop the fetchmail process).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1427.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"fetchmail", rpm:"fetchmail~6.2.0~3.el3.5", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail-debuginfo", rpm:"fetchmail-debuginfo~6.2.0~3.el3.5", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail", rpm:"fetchmail~6.2.5~6.0.1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail-debuginfo", rpm:"fetchmail-debuginfo~6.2.5~6.0.1.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail", rpm:"fetchmail~6.3.6~1.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"fetchmail-debuginfo", rpm:"fetchmail-debuginfo~6.3.6~1.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
