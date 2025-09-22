# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63204");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
  script_cve_id("CVE-2007-5963");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:017 (kdebase)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(3\.0|4\.0)");
  script_tag(name:"insight", value:"A vulnerability in KDM allowed a local user to cause a denial of
service via unknown vectors (CVE-2007-5963).

The updated packages have been patched to prevent this issue.

Affected: Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:017");
  script_tag(name:"summary", value:"The remote host is missing an update to kdebase
announced via advisory MDVSA-2009:017.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdebase", rpm:"kdebase~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common", rpm:"kdebase-common~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kate", rpm:"kdebase-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-data", rpm:"kdebase-kcontrol-data~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdeprintfax", rpm:"kdebase-kdeprintfax~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm", rpm:"kdebase-kdm~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm-config-file", rpm:"kdebase-kdm-config-file~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kmenuedit", rpm:"kdebase-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-konsole", rpm:"kdebase-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-nsplugins", rpm:"kdebase-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-progs", rpm:"kdebase-progs~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4", rpm:"libkdebase4~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel", rpm:"libkdebase4-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate", rpm:"libkdebase4-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate-devel", rpm:"libkdebase4-kate-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kmenuedit", rpm:"libkdebase4-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-konsole", rpm:"libkdebase4-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-nsplugins", rpm:"libkdebase4-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-nsplugins-devel", rpm:"libkdebase4-nsplugins-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4", rpm:"lib64kdebase4~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel", rpm:"lib64kdebase4-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate", rpm:"lib64kdebase4-kate~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate-devel", rpm:"lib64kdebase4-kate-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kmenuedit", rpm:"lib64kdebase4-kmenuedit~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-konsole", rpm:"lib64kdebase4-konsole~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-nsplugins", rpm:"lib64kdebase4-nsplugins~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-nsplugins-devel", rpm:"lib64kdebase4-nsplugins-devel~3.2~79.20.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase", rpm:"kdebase~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common", rpm:"kdebase-common~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-common-doc", rpm:"kdebase-common-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kate", rpm:"kdebase-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-data", rpm:"kdebase-kcontrol-data~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kcontrol-doc", rpm:"kdebase-kcontrol-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdeprintfax", rpm:"kdebase-kdeprintfax~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kdm", rpm:"kdebase-kdm~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-kmenuedit", rpm:"kdebase-kmenuedit~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-konsole", rpm:"kdebase-konsole~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-nsplugins", rpm:"kdebase-nsplugins~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdebase-progs", rpm:"kdebase-progs~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkateinterfaces0", rpm:"libkateinterfaces0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkateutils0", rpm:"libkateutils0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4", rpm:"libkdebase4~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel", rpm:"libkdebase4-devel~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-devel-doc", rpm:"libkdebase4-devel-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libkdebase4-kate", rpm:"libkdebase4-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kateinterfaces0", rpm:"lib64kateinterfaces0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kateutils0", rpm:"lib64kateutils0~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4", rpm:"lib64kdebase4~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel", rpm:"lib64kdebase4-devel~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-devel-doc", rpm:"lib64kdebase4-devel-doc~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64kdebase4-kate", rpm:"lib64kdebase4-kate~3.5.4~2.5.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
