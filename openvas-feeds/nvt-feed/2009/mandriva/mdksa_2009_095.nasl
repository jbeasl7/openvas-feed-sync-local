# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63873");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792", "CVE-2009-0196");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:095 (ghostscript)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|4\.0)");
  script_tag(name:"insight", value:"A buffer underflow in Ghostscript's CCITTFax decoding filter allows
remote attackers to cause denial of service and possibly to execute
arbitrary by using a crafted PDF file (CVE-2007-6725).

Buffer overflow in Ghostscript's BaseFont writer module allows
remote attackers to cause a denial of service and possibly to execute
arbitrary code via a crafted Postscript file (CVE-2008-6679).

Multiple integer overflows in Ghostscript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images (CVE-2009-0583, CVE-2009-0584).

Multiple integer overflows in Ghostscript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images. Note: this issue exists because of
an incomplete fix for CVE-2009-0583 (CVE-2009-0792).

Heap-based overflow in Ghostscript's JBIG2 decoding library allows
attackers to cause denial of service and possibly to execute arbitrary
code by using a crafted PDF file (CVE-2009-0196).

This update provides fixes for that vulnerabilities.

Update:

gostscript packages from Mandriva Linux 2009.0 distribution are not
affected by CVE-2007-6725.

Affected: 2008.1, 2009.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:095");
  script_tag(name:"summary", value:"The remote host is missing an update to ghostscript
announced via advisory MDVSA-2009:095.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8", rpm:"libgs8~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8-devel", rpm:"libgs8-devel~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1-devel", rpm:"libijs1-devel~0.35~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8", rpm:"lib64gs8~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8-devel", rpm:"lib64gs8-devel~8.61~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1-devel", rpm:"lib64ijs1-devel~0.35~60.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8", rpm:"libgs8~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8-devel", rpm:"libgs8-devel~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1-devel", rpm:"libijs1-devel~0.35~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8", rpm:"lib64gs8~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8-devel", rpm:"lib64gs8-devel~8.63~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1-devel", rpm:"lib64ijs1-devel~0.35~62.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8", rpm:"libgs8~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgs8-devel", rpm:"libgs8-devel~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libijs1-devel", rpm:"libijs1-devel~0.35~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8", rpm:"lib64gs8~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gs8-devel", rpm:"lib64gs8-devel~8.15~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ijs1-devel", rpm:"lib64ijs1-devel~0.35~46.2.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
