# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64941");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-2473", "CVE-2009-2474");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("RedHat Security Advisory RHSA-2009:1452");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1452.

neon is an HTTP and WebDAV client library, with a C interface. It provides
a high-level interface to HTTP and WebDAV methods along with a low-level
interface for HTTP request handling. neon supports persistent connections,
proxy servers, basic, digest and Kerberos authentication, and has complete
SSL support.

It was discovered that neon is affected by the previously published null
prefix attack, caused by incorrect handling of NULL characters in X.509
certificates. If an attacker is able to get a carefully-crafted certificate
signed by a trusted Certificate Authority, the attacker could use the
certificate during a man-in-the-middle attack and potentially confuse an
application using the neon library into accepting it by mistake.
(CVE-2009-2474)

A denial of service flaw was found in the neon Extensible Markup Language
(XML) parser. A remote attacker (malicious DAV server) could provide a
specially-crafted XML document that would cause excessive memory and CPU
consumption if an application using the neon XML parser was tricked into
processing it. (CVE-2009-2473)

All neon users should upgrade to these updated packages, which contain
backported patches to correct these issues. Applications using the neon
HTTP and WebDAV client library, such as cadaver, must be restarted for this
update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1452.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"neon", rpm:"neon~0.24.7~4.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-debuginfo", rpm:"neon-debuginfo~0.24.7~4.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-devel", rpm:"neon-devel~0.24.7~4.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon", rpm:"neon~0.25.5~10.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-debuginfo", rpm:"neon-debuginfo~0.25.5~10.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"neon-devel", rpm:"neon-devel~0.25.5~10.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
