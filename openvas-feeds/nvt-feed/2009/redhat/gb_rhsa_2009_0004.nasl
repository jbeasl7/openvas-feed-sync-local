# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63112");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
  script_cve_id("CVE-2008-5077");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0004");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(2\.1|3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0004.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
Transport Layer Security (TLS v1) protocols as well as a full-strength,
general purpose, cryptography library.

The Google security team discovered a flaw in the way OpenSSL checked the
verification of certificates. An attacker in control of a malicious server,
or able to effect a man in the middle attack, could present a malformed
SSL/TLS signature from a certificate chain to a vulnerable client and
bypass validation. (CVE-2008-5077)

All OpenSSL users should upgrade to these updated packages, which contain
backported patches to resolve these issues. For the update to take effect,
all running OpenSSL client applications must be restarted, or the system
rebooted.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0004.html");
  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20090107.txt");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.6b~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.6b~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.6b~49", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl095a", rpm:"openssl095a~0.9.5a~34", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl096", rpm:"openssl096~0.9.6~34", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7a~33.25", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.7a~33.25", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.7a~33.25", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.7a~33.25", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl096b", rpm:"openssl096b~0.9.6b~16.49", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl096b-debuginfo", rpm:"openssl096b-debuginfo~0.9.6b~16.49", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.7a~43.17.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.7a~43.17.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.7a~43.17.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.7a~43.17.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl096b", rpm:"openssl096b~0.9.6b~22.46.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl096b-debuginfo", rpm:"openssl096b-debuginfo~0.9.6b~22.46.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8b~10.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~0.9.8b~10.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8b~10.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl097a", rpm:"openssl097a~0.9.7a~9.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl097a-debuginfo", rpm:"openssl097a-debuginfo~0.9.7a~9.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8b~10.el5_2.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
