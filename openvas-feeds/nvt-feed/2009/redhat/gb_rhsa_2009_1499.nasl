# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66010");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
  script_cve_id("CVE-2009-2979", "CVE-2009-2980", "CVE-2009-2981", "CVE-2009-2983", "CVE-2009-2985", "CVE-2009-2986", "CVE-2009-2988", "CVE-2009-2990", "CVE-2009-2991", "CVE-2009-2993", "CVE-2009-2994", "CVE-2009-2996", "CVE-2009-2997", "CVE-2009-2998", "CVE-2009-3431", "CVE-2009-3458", "CVE-2009-3459", "CVE-2009-3462");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1499");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1499.

Adobe Reader allows users to view and print documents in Portable Document
Format (PDF).

Multiple flaws were discovered in Adobe Reader. A specially-crafted PDF
file could cause Adobe Reader to crash or, potentially, execute arbitrary
code as the user running Adobe Reader when opened. (CVE-2009-2980,
CVE-2009-2983, CVE-2009-2985, CVE-2009-2986, CVE-2009-2990, CVE-2009-2991,
CVE-2009-2993, CVE-2009-2994, CVE-2009-2996, CVE-2009-2997, CVE-2009-2998,
CVE-2009-3458, CVE-2009-3459, CVE-2009-3462)

Multiple flaws were discovered in Adobe Reader. A specially-crafted PDF
file could cause Adobe Reader to crash when opened. (CVE-2009-2979,
CVE-2009-2988, CVE-2009-3431)

An input validation flaw was found in Adobe Reader. Opening a
specially-crafted PDF file could lead to a Trust Manager restrictions
bypass. (CVE-2009-2981)

All Adobe Reader users should install these updated packages. They contain
Adobe Reader version 8.1.7, which is not vulnerable to these issues. All
running instances of Adobe Reader must be restarted for the update to take
effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1499.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.7~1", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread-plugin", rpm:"acroread-plugin~8.1.7~1", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.7~1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread-plugin", rpm:"acroread-plugin~8.1.7~1.el4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread", rpm:"acroread~8.1.7~1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"acroread-plugin", rpm:"acroread-plugin~8.1.7~1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
