# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64595");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-1891", "CVE-2009-2412");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1205");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_3");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1205.

The Apache HTTP Server is a popular Web server. The httpd package shipped
with Red Hat Enterprise Linux 3 contains embedded copies of the Apache
Portable Runtime (APR) libraries, which provide a free library of C data
structures and routines, and also additional utility interfaces to support
XML parsing, LDAP, database interfaces, URI parsing, and more.

Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in the way the Apache Portable Runtime (APR) manages memory pool
and relocatable memory allocations. An attacker could use these flaws to
issue a specially-crafted request for memory allocation, which would lead
to a denial of service (application crash) or, potentially, execute
arbitrary code with the privileges of an application using the APR
libraries. (CVE-2009-2412)

A denial of service flaw was found in the Apache mod_deflate module. This
module continued to compress large files until compression was complete,
even if the network connection that requested the content was closed
before compression completed. This would cause mod_deflate to consume
large amounts of CPU if mod_deflate was enabled for a large file.
(CVE-2009-1891)

This update also fixes the following bug:

  * in some cases the Content-Length header was dropped from HEAD responses.
This resulted in certain sites not working correctly with mod_proxy, such
as www.windowsupdate.com. (BZ#506016)

All httpd users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the updated
packages, the httpd daemon must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1205.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~75.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.0.46~75.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~75.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~75.ent", rls:"RHENT_3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
