# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64993");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
  script_cve_id("CVE-2007-2027", "CVE-2008-7224");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1471");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1471.

ELinks is a text-based Web browser. ELinks does not display any images, but
it does support frames, tables, and most other HTML tags.

An off-by-one buffer overflow flaw was discovered in the way ELinks handled
its internal cache of string representations for HTML special entities. A
remote attacker could use this flaw to create a specially-crafted HTML file
that would cause ELinks to crash or, possibly, execute arbitrary code when
rendered. (CVE-2008-7224)

It was discovered that ELinks tried to load translation files using
relative paths. A local attacker able to trick a victim into running ELinks
in a folder containing specially-crafted translation files could use this
flaw to confuse the victim via incorrect translations, or cause ELinks to
crash and possibly execute arbitrary code via embedded formatting sequences
in translated messages. (CVE-2007-2027)

All ELinks users are advised to upgrade to this updated package, which
contains backported patches to resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1471.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.9.2~4.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"elinks-debuginfo", rpm:"elinks-debuginfo~0.9.2~4.el4_8.1", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.11.1~6.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"elinks-debuginfo", rpm:"elinks-debuginfo~0.11.1~6.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
