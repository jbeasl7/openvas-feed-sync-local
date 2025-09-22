# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66493");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-1179", "CVE-2009-0791", "CVE-2009-1709", "CVE-2009-0945");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:331 (kdegraphics)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_4\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in kdegraphics:

Multiple buffer overflows in the JBIG2 decoder in Xpdf 3.02pl2
and earlier allow remote attackers to cause a denial of service
(crash) via a crafted PDF file, related to (1) setBitmap and (2)
readSymbolDictSeg (CVE-2009-0146).

Multiple integer overflows in the JBIG2 decoder in Xpdf 3.02pl2 and
earlier allow remote attackers to cause a denial of service (crash)
via a crafted PDF file (CVE-2009-0147).

The JBIG2 decoder in Xpdf 3.02pl2 and earlier allows remote attackers
to cause a denial of service (crash) via a crafted PDF file that
triggers a free of uninitialized memory (CVE-2009-0166).

Multiple integer overflows in the pdftops filter in CUPS 1.1.17,
1.1.22, and 1.3.7 allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
PDF file that triggers a heap-based buffer overflow, possibly
related to (1) Decrypt.cxx, (2) FoFiTrueType.cxx, (3) gmem.c, (4)
JBIG2Stream.cxx, and (5) PSOutputDev.cxx in pdftops/.  NOTE: the
JBIG2Stream.cxx vector may overlap CVE-2009-1179. (CVE-2009-0791).

Use-after-free vulnerability in the garbage-collection implementation
in WebCore in WebKit in Apple Safari before 4.0 allows remote
attackers to execute arbitrary code or cause a denial of service
(heap corruption and application crash) via an SVG animation element,
related to SVG set objects, SVG marker elements, the targetElement
attribute, and unspecified caches. (CVE-2009-1709).

WebKit, as used in Safari before 3.2.3 and 4 Public Beta, on Apple
Mac OS X 10.4.11 and 10.5 before 10.5.7 and Windows allows remote
attackers to execute arbitrary code via a crafted SVGList object that
triggers memory corruption (CVE-2009-0945).

This update provides a solution to this vulnerability.

Affected: Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:331");
  script_tag(name:"summary", value:"The remote host is missing an update to kdegraphics
announced via advisory MDVSA-2009:331.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-common", rpm:"kdegraphics-common~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kcolorchooser", rpm:"kdegraphics-kcolorchooser~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kcoloredit", rpm:"kdegraphics-kcoloredit~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kdvi", rpm:"kdegraphics-kdvi~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kfax", rpm:"kdegraphics-kfax~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kghostview", rpm:"kdegraphics-kghostview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kiconedit", rpm:"kdegraphics-kiconedit~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kolourpaint", rpm:"kdegraphics-kolourpaint~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kooka", rpm:"kdegraphics-kooka~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kpdf", rpm:"kdegraphics-kpdf~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kpovmodeler", rpm:"kdegraphics-kpovmodeler~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kruler", rpm:"kdegraphics-kruler~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-ksnapshot", rpm:"kdegraphics-ksnapshot~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-ksvg", rpm:"kdegraphics-ksvg~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kuickshow", rpm:"kdegraphics-kuickshow~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-kview", rpm:"kdegraphics-kview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-mrmlsearch", rpm:"kdegraphics-mrmlsearch~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-common", rpm:"libkdegraphics0-common~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-common-devel", rpm:"libkdegraphics0-common-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview", rpm:"libkdegraphics0-kghostview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview-devel", rpm:"libkdegraphics0-kghostview-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka", rpm:"libkdegraphics0-kooka~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka-devel", rpm:"libkdegraphics0-kooka-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler", rpm:"libkdegraphics0-kpovmodeler~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler-devel", rpm:"libkdegraphics0-kpovmodeler-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg", rpm:"libkdegraphics0-ksvg~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg-devel", rpm:"libkdegraphics0-ksvg-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kview", rpm:"libkdegraphics0-kview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdegraphics0-kview-devel", rpm:"libkdegraphics0-kview-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common", rpm:"lib64kdegraphics0-common~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common-devel", rpm:"lib64kdegraphics0-common-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview", rpm:"lib64kdegraphics0-kghostview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview-devel", rpm:"lib64kdegraphics0-kghostview-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka", rpm:"lib64kdegraphics0-kooka~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka-devel", rpm:"lib64kdegraphics0-kooka-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler", rpm:"lib64kdegraphics0-kpovmodeler~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler-devel", rpm:"lib64kdegraphics0-kpovmodeler-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg", rpm:"lib64kdegraphics0-ksvg~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg-devel", rpm:"lib64kdegraphics0-ksvg-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview", rpm:"lib64kdegraphics0-kview~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview-devel", rpm:"lib64kdegraphics0-kview-devel~3.5.4~0.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
