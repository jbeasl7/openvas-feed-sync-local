# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63206");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2008-5187");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:019 (imlib2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.0|2008\.1|2009\.0|3\.0|4\.0)");
  script_tag(name:"insight", value:"A vulnerability have been discovered in the load function of the XPM
loader for imlib2, which allows attackers to cause a denial of service
(crash) and possibly execute arbitrary code via a crafted XPM file
(CVE-2008-5187).

The updated packages have been patched to prevent this.

Affected: 2008.0, 2008.1, 2009.0, Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:019");
  script_tag(name:"summary", value:"The remote host is missing an update to imlib2
announced via advisory MDVSA-2009:019.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.0.003~2.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.0.003~4.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2-devel", rpm:"libimlib2-devel~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2-devel", rpm:"lib64imlib2-devel~1.4.1.000~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-devel", rpm:"libimlib2_1-devel~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-devel", rpm:"lib64imlib2_1-devel~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.0.6~4.6.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imlib2-data", rpm:"imlib2-data~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1", rpm:"libimlib2_1~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-devel", rpm:"libimlib2_1-devel~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-filters", rpm:"libimlib2_1-filters~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libimlib2_1-loaders", rpm:"libimlib2_1-loaders~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1", rpm:"lib64imlib2_1~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-devel", rpm:"lib64imlib2_1-devel~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-filters", rpm:"lib64imlib2_1-filters~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64imlib2_1-loaders", rpm:"lib64imlib2_1-loaders~1.2.1~1.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
