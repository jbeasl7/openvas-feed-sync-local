# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63875");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2009-1241", "CVE-2008-6680", "CVE-2009-1270", "CVE-2009-1371", "CVE-2009-1372");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:097 (clamav)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|3\.0|4\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in clamav:

Unspecified vulnerability in ClamAV before 0.95 allows remote
attackers to bypass detection of malware via a modified RAR archive
(CVE-2009-1241).

libclamav/pe.c in ClamAV before 0.95 allows remote attackers to cause
a denial of service (crash) via a crafted EXE file that triggers a
divide-by-zero error (CVE-2008-6680).

libclamav/untar.c in ClamAV before 0.95 allows remote attackers to
cause a denial of service (infinite loop) via a crafted file that
causes (1) clamd and (2) clamscan to hang (CVE-2009-1270).

The CLI_ISCONTAINED macro in libclamav/others.h in ClamAV before 0.95.1
allows remote attackers to cause a denial of service (application
crash) via a malformed file with UPack encoding (CVE-2009-1371).

Stack-based buffer overflow in the cli_url_canon function in
libclamav/phishcheck.c in ClamAV before 0.95.1 allows remote attackers
to cause a denial of service (application crash) and possibly execute
arbitrary code via a crafted URL (CVE-2009-1372).

Important notice about this upgrade: clamav-0.95+ bundles support
for RAR v3 in libclamav which is a license violation as the RAR v3
license and the GPL license is not compatible. As a consequence to
this Mandriva has been forced to remove the RAR v3 code.

This update provides clamav 0.95.1, which is not vulnerable to
these issues.

Affected: 2008.1, 2009.0, Corporate 3.0, Corporate 4.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:097");
  script_tag(name:"summary", value:"The remote host is missing an update to clamav
announced via advisory MDVSA-2009:097.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.95.1~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.95.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.95.1~1.1.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav6", rpm:"libclamav6~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav6", rpm:"lib64clamav6~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.95.1~1.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
