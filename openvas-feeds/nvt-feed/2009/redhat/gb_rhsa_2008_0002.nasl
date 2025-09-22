# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64178");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
  script_cve_id("CVE-2008-0003");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2008:0002");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date.");

  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2008-0002.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_tag(name:"insight", value:"The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
Management (WBEM) services. WBEM is a platform and resource independent
DMTF standard that defines a common information model, and communication
protocol for monitoring and controlling resources.

During a security audit, a stack buffer overflow flaw was found in the PAM
authentication code in the OpenPegasus CIM management server. An
unauthenticated remote user could trigger this flaw and potentially execute
arbitrary code with root privileges. (CVE-2008-0003)

Note that the tog-pegasus packages are not installed by default on Red Hat
Enterprise Linux. The Red Hat Security Response Team believes that it would
be hard to remotely exploit this issue to execute arbitrary code, due to
the default SELinux targeted policy on Red Hat Enterprise Linux 4 and 5,
and the SELinux memory protection tests enabled by default on Red Hat
Enterprise Linux 5.

Users of tog-pegasus should upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
updated packages the tog-pegasus service should be restarted.");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2008:0002.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-test", rpm:"tog-pegasus-test~2.5.1~5.el4_6.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-test", rpm:"tog-pegasus-test~2.5.1~2.el4_5.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.6.1~2.el5_1.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
