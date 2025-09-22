# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64695");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
  script_cve_id("CVE-2009-1885");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:223 (xerces-c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|mes5)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in xerces-c:

Stack consumption vulnerability in validators/DTD/DTDScanner.cpp in
Apache Xerces C++ 2.7.0 and 2.8.0 allows context-dependent attackers to
cause a denial of service (application crash) via vectors involving
nested parentheses and invalid byte values in simply nested DTD
structures, as demonstrated by the Codenomicon XML fuzzing framework
(CVE-2009-1885).

This update provides a solution to this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:223");
  script_tag(name:"summary", value:"The remote host is missing an update to xerces-c
announced via advisory MDVSA-2009:223.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libxerces-c0", rpm:"libxerces-c0~2.7.0~7.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c0-devel", rpm:"libxerces-c0-devel~2.7.0~7.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.7.0~7.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0", rpm:"lib64xerces-c0~2.7.0~7.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0-devel", rpm:"lib64xerces-c0-devel~2.7.0~7.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c0", rpm:"libxerces-c0~2.7.0~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c0-devel", rpm:"libxerces-c0-devel~2.7.0~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c28", rpm:"libxerces-c28~2.8.0~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c-devel", rpm:"libxerces-c-devel~2.8.0~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.7.0~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.8.0~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0", rpm:"lib64xerces-c0~2.7.0~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0-devel", rpm:"lib64xerces-c0-devel~2.7.0~7.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c28", rpm:"lib64xerces-c28~2.8.0~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c-devel", rpm:"lib64xerces-c-devel~2.8.0~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c28", rpm:"libxerces-c28~2.8.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c-devel", rpm:"libxerces-c-devel~2.8.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.8.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c28", rpm:"lib64xerces-c28~2.8.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c-devel", rpm:"lib64xerces-c-devel~2.8.0~2.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c0", rpm:"libxerces-c0~2.7.0~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c0-devel", rpm:"libxerces-c0-devel~2.7.0~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c28", rpm:"libxerces-c28~2.8.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxerces-c-devel", rpm:"libxerces-c-devel~2.8.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.7.0~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~2.8.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0", rpm:"lib64xerces-c0~2.7.0~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c0-devel", rpm:"lib64xerces-c0-devel~2.7.0~7.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c28", rpm:"lib64xerces-c28~2.8.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xerces-c-devel", rpm:"lib64xerces-c-devel~2.8.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
