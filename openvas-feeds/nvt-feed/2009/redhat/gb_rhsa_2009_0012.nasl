# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63368");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_cve_id("CVE-2007-2721", "CVE-2008-3520");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:0012");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0012.

The netpbm package contains a library of functions for editing and
converting between various graphics file formats, including .pbm (portable
bitmaps), .pgm (portable graymaps), .pnm (portable anymaps), .ppm (portable
pixmaps), and others.

An input validation flaw and multiple integer overflows were discovered in
the JasPer library providing support for JPEG-2000 image format and used in
the jpeg2ktopam and pamtojpeg2k converters. An attacker could create a
carefully-crafted JPEG file which could cause jpeg2ktopam to crash or,
possibly, execute arbitrary code as the user running jpeg2ktopam.
(CVE-2007-2721, CVE-2008-3520)

All users are advised to upgrade to these updated packages which contain
backported patches which resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0012.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#moderate");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.25~2.1.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.25~2.1.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.25~2.1.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.25~2.1.el4_7.4", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.35~6.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.35~6.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.35~6.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.35~6.1.el5_3.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
