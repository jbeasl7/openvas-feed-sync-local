# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66086");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-3293", "CVE-2009-3546");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:284 (gd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2009\.0|2009\.1|3\.0|4\.0|mes5|2\.0)");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in gd:

The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.0, and the
GD Graphics Library 2.x, does not properly verify a certain colorsTotal
structure member, which might allow remote attackers to conduct
buffer overflow or buffer over-read attacks via a crafted GD file,
a different vulnerability than CVE-2009-3293.  NOTE: some of these
details are obtained from third party information (CVE-2009-3546).

This update fixes this vulnerability.

Affected: 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:284");
  script_tag(name:"summary", value:"The remote host is missing an update to gd
announced via advisory MDVSA-2009:284.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.0.35~6.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.0.35~8.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.15~4.3.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.33~3.6.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.0.35~6.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.15~4.3.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.15~4.3.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.15~4.3.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.15~4.3.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
