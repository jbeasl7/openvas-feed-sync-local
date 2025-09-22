# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64529");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2009-2620");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:186 (firebird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in firebird:

src/remote/server.cpp in fbserver.exe in Firebird SQL 1.5 before
1.5.6, 2.0 before 2.0.6, 2.1 before 2.1.3, and 2.5 before 2.5 Beta 2
allows remote attackers to cause a denial of service (daemon crash)
via a malformed op_connect_request message that triggers an infinite
loop or NULL pointer dereference (CVE-2009-2620).

This update provides fixes for this vulnerability.

Affected: Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:186");
  script_tag(name:"summary", value:"The remote host is missing an update to firebird
announced via advisory MDVSA-2009:186.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-server-classic", rpm:"firebird-server-classic~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-server-common", rpm:"firebird-server-common~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-server-superserver", rpm:"firebird-server-superserver~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-utils-classic", rpm:"firebird-utils-classic~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firebird-utils-superserver", rpm:"firebird-utils-superserver~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libfbembed2", rpm:"libfbembed2~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64fbclient2", rpm:"lib64fbclient2~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64fbembed2", rpm:"lib64fbembed2~2.1.1.17910.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
