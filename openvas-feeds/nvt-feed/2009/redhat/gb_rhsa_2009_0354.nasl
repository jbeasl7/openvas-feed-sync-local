# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63580");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0354");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0354.

Evolution Data Server provides a unified back-end for applications which
interact with contacts, task, and calendar information. Evolution Data
Server was originally developed as a back-end for Evolution, but is now
used by multiple other applications.

Evolution Data Server did not properly check the Secure/Multipurpose
Internet Mail Extensions (S/MIME) signatures used for public key encryption
and signing of e-mail messages. An attacker could use this flaw to spoof a
signature by modifying the text of the e-mail message displayed to the
user. (CVE-2009-0547)

It was discovered that Evolution Data Server did not properly validate NTLM
(NT LAN Manager) authentication challenge packets. A malicious server using
NTLM authentication could cause an application using Evolution Data Server
to disclose portions of its memory or crash during user authentication.
(CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by Evolution Data
Server. This could cause an application using Evolution Data Server to
crash, or, possibly, execute an arbitrary code when large untrusted data
blocks were Base64-encoded. (CVE-2009-0587)

All users of evolution-data-server and evolution28-evolution-data-server
are advised to upgrade to these updated packages, which contain backported
patches to correct these issues. All running instances of Evolution Data
Server and applications using it (such as Evolution) must be restarted for
the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0354.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"evolution28-evolution-data-server", rpm:"evolution28-evolution-data-server~1.8.0~37.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution28-evolution-data-server-debuginfo", rpm:"evolution28-evolution-data-server-debuginfo~1.8.0~37.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution28-evolution-data-server-devel", rpm:"evolution28-evolution-data-server-devel~1.8.0~37.el4_7.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~1.12.3~10.el5_3.3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-debuginfo", rpm:"evolution-data-server-debuginfo~1.12.3~10.el5_3.3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-doc", rpm:"evolution-data-server-doc~1.12.3~10.el5_3.3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~1.12.3~10.el5_3.3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
