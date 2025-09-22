# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66242");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
  script_cve_id("CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1582");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1582.

The IBM 1.6.0 Java release includes the IBM Java 2 Runtime Environment and
the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. These
vulnerabilities are summarized on the IBM Security alerts page listed in
the References section. (CVE-2009-2625, CVE-2009-2670, CVE-2009-2671,
CVE-2009-2672, CVE-2009-2673, CVE-2009-2674, CVE-2009-2675, CVE-2009-2676)

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.6.0 SR6 Java release. All running instances
of IBM Java must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1582.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm", rpm:"java-1.6.0-ibm~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-demo", rpm:"java-1.6.0-ibm-demo~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-devel", rpm:"java-1.6.0-ibm-devel~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-javacomm", rpm:"java-1.6.0-ibm-javacomm~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-jdbc", rpm:"java-1.6.0-ibm-jdbc~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-plugin", rpm:"java-1.6.0-ibm-plugin~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-src", rpm:"java-1.6.0-ibm-src~1.6.0.6~1jpp.3.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm", rpm:"java-1.6.0-ibm~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-accessibility", rpm:"java-1.6.0-ibm-accessibility~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-demo", rpm:"java-1.6.0-ibm-demo~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-devel", rpm:"java-1.6.0-ibm-devel~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-javacomm", rpm:"java-1.6.0-ibm-javacomm~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-jdbc", rpm:"java-1.6.0-ibm-jdbc~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-plugin", rpm:"java-1.6.0-ibm-plugin~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"java-1.6.0-ibm-src", rpm:"java-1.6.0-ibm-src~1.6.0.6~1jpp.3.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
