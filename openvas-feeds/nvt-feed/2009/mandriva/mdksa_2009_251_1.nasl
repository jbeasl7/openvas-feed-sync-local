# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66478");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-3229", "CVE-2007-6600", "CVE-2009-3230", "CVE-2009-3231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:251-1 (postgresql8.2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"The core server component in PostgreSQL 8.4 before 8.4.1, 8.3 before
8.3.8, and 8.2 before 8.2.14 allows remote authenticated users to
cause a denial of service (backend shutdown) by re-LOAD-ing libraries
from a certain plugins directory (CVE-2009-3229).

The core server component in PostgreSQL 8.4 before 8.4.1, 8.3 before
8.3.8, 8.2 before 8.2.14, 8.1 before 8.1.18, 8.0 before 8.0.22,
and 7.4 before 7.4.26 does not use the appropriate privileges for
the (1) RESET ROLE and (2) RESET SESSION AUTHORIZATION operations,
which allows remote authenticated users to gain privileges.  NOTE:
this is due to an incomplete fix for CVE-2007-6600 (CVE-2009-3230).

The core server component in PostgreSQL 8.3 before 8.3.8 and 8.2
before 8.2.14, when using LDAP authentication with anonymous binds,
allows remote attackers to bypass authentication via an empty password
(CVE-2009-3231).

This update provides a fix for this vulnerability.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:251-1");
  script_tag(name:"summary", value:"The remote host is missing an update to postgresql8.2
announced via advisory MDVSA-2009:251-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libecpg5", rpm:"libecpg5~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libecpg-devel", rpm:"libecpg-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpq-devel", rpm:"libpq-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2", rpm:"postgresql8.2~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-contrib", rpm:"postgresql8.2-contrib~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-devel", rpm:"postgresql8.2-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-docs", rpm:"postgresql8.2-docs~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-pl", rpm:"postgresql8.2-pl~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plperl", rpm:"postgresql8.2-plperl~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plpgsql", rpm:"postgresql8.2-plpgsql~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-plpython", rpm:"postgresql8.2-plpython~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-pltcl", rpm:"postgresql8.2-pltcl~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-server", rpm:"postgresql8.2-server~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql8.2-test", rpm:"postgresql8.2-test~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg5", rpm:"lib64ecpg5~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ecpg-devel", rpm:"lib64ecpg-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq5", rpm:"lib64pq5~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64pq-devel", rpm:"lib64pq-devel~8.2.14~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
