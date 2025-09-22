# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63434");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-03-02 19:11:09 +0100 (Mon, 02 Mar 2009)");
  script_cve_id("CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0521");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0332");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0332.

The flash-plugin package contains a Firefox-compatible Adobe Flash Player
Web browser plug-in.

Multiple input validation flaws were found in the way Flash Player
displayed certain SWF (Shockwave Flash) content. An attacker could use
these flaws to create a specially-crafted SWF file that could cause
flash-plugin to crash, or, possibly, execute arbitrary code when the victim
loaded a page containing the specially-crafted SWF content. (CVE-2009-0520,
CVE-2009-0519)

It was discovered that Adobe Flash Player had an insecure RPATH (runtime
library search path) set in the ELF (Executable and Linking Format) header.
A local user with write access to the directory pointed to by RPATH could
use this flaw to execute arbitrary code with the privileges of the user
running Adobe Flash Player. (CVE-2009-0521)

All users of Adobe Flash Player should install this updated package, which
upgrades Flash Player to version 10.0.22.87.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0332.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#critical");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-01.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"flash-plugin", rpm:"flash-plugin~10.0.22.87~1.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
