# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66238");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3873", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1571");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1571.

The Sun 1.5.0 Java release includes the Sun Java 5 Runtime Environment and
the Sun Java 5 Software Development Kit.

This update fixes several vulnerabilities in the Sun Java 5 Runtime
Environment and the Sun Java 5 Software Development Kit. These
vulnerabilities are summarized on the Advance notification of Security
Updates for Java SE page from Sun Microsystems, listed in the References
section. (CVE-2009-2409, CVE-2009-3728, CVE-2009-3873, CVE-2009-3876,
CVE-2009-3877, CVE-2009-3879, CVE-2009-3880, CVE-2009-3881, CVE-2009-3882,
CVE-2009-3883, CVE-2009-3884)

Note: This is the final update for the java-1.5.0-sun packages, as the Sun
Java SE Release family 5.0 has now reached End of Service Life. The next
update will remove the java-1.5.0-sun packages.

An alternative to Sun Java SE 5.0 is the Java 2 Technology Edition of the
IBM Developer Kit for Linux, which is available from the Extras and
Supplementary channels on the Red Hat Network. For users of applications
that are capable of using the Java 6 runtime, the OpenJDK open source JDK
is included in Red Hat Enterprise Linux 5 (since 5.3) and is supported by
Red Hat.

Users of java-1.5.0-sun should upgrade to these updated packages, which
correct these issues. All running instances of Sun Java must be restarted
for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1571.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://blogs.sun.com/security/entry/advance_notification_of_security_updates6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"java-1.5.0-sun", rpm:"java-1.5.0-sun~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-demo", rpm:"java-1.5.0-sun-demo~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-devel", rpm:"java-1.5.0-sun-devel~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-jdbc", rpm:"java-1.5.0-sun-jdbc~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-plugin", rpm:"java-1.5.0-sun-plugin~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-src", rpm:"java-1.5.0-sun-src~1.5.0.22~1jpp.1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun", rpm:"java-1.5.0-sun~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-demo", rpm:"java-1.5.0-sun-demo~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-devel", rpm:"java-1.5.0-sun-devel~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-jdbc", rpm:"java-1.5.0-sun-jdbc~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-plugin", rpm:"java-1.5.0-sun-plugin~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.5.0-sun-src", rpm:"java-1.5.0-sun-src~1.5.0.22~1jpp.1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
