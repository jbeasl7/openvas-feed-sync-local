# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63765");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
  script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0792", "CVE-2009-0583");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0421");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0421.

Ghostscript is a set of software that provides a PostScript interpreter, a
set of C procedures (the Ghostscript library, which implements the graphics
capabilities in the PostScript language) and an interpreter for Portable
Document Format (PDF) files.

It was discovered that the Red Hat Security Advisory RHSA-2009:0345 did not
address all possible integer overflow flaws in Ghostscript's International
Color Consortium Format library (icclib). Using specially-crafted ICC
profiles, an attacker could create a malicious PostScript or PDF file with
embedded images that could cause Ghostscript to crash or, potentially,
execute arbitrary code when opened. (CVE-2009-0792)

A buffer overflow flaw and multiple missing boundary checks were found in
Ghostscript. An attacker could create a specially-crafted PostScript or PDF
file that could cause Ghostscript to crash or, potentially, execute
arbitrary code when opened. (CVE-2008-6679, CVE-2007-6725, CVE-2009-0196)

Red Hat would like to thank Alin Rad Pop of Secunia Research for
responsibly reporting the CVE-2009-0196 flaw.

Users of ghostscript are advised to upgrade to these updated packages,
which contain backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0421.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.15.2~9.4.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~8.15.2~9.4.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~8.15.2~9.4.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~8.15.2~9.4.el5_3.7", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
