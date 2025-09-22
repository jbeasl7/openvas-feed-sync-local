# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64133");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:121 (lcms)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0)");
  script_tag(name:"insight", value:"Multiple security vulnerabilities has been identified and fixed in
Little cms:

A memory leak flaw allows remote attackers to cause a denial of service
(memory consumption and application crash) via a crafted image file
(CVE-2009-0581).

Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).

Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a large
integer value for the (1) input or (2) output channel (CVE-2009-0733).

A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).

This update provides fixes for these issues.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:121");
  script_tag(name:"summary", value:"The remote host is missing an update to lcms
announced via advisory MDVSA-2009:121.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"lcms", rpm:"lcms~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1", rpm:"liblcms1~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms-devel", rpm:"liblcms-devel~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-lcms", rpm:"python-lcms~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1", rpm:"lib64lcms1~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms-devel", rpm:"lib64lcms-devel~1.18~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lcms", rpm:"lcms~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1", rpm:"liblcms1~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms-devel", rpm:"liblcms-devel~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-lcms", rpm:"python-lcms~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1", rpm:"lib64lcms1~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms-devel", rpm:"lib64lcms-devel~1.18~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lcms", rpm:"lcms~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1", rpm:"liblcms1~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms-devel", rpm:"liblcms-devel~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-lcms", rpm:"python-lcms~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1", rpm:"lib64lcms1~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms-devel", rpm:"lib64lcms-devel~1.18~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1", rpm:"liblcms1~1.10~1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1-devel", rpm:"liblcms1-devel~1.10~1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1", rpm:"lib64lcms1~1.10~1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1-devel", rpm:"lib64lcms1-devel~1.10~1.2.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1", rpm:"liblcms1~1.14~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"liblcms1-devel", rpm:"liblcms1-devel~1.14~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1", rpm:"lib64lcms1~1.14~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64lcms1-devel", rpm:"lib64lcms1-devel~1.14~1.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
