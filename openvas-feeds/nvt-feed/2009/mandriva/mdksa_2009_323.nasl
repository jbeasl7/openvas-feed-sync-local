# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66414");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2008-1678", "CVE-2009-1191", "CVE-2008-2939", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891", "CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:323 (apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"For details on the issues addressed with this update, please
visit the referenced security advisories.

Packages for 2008.0 are being provided due to extended support for
Corporate products.

This update provides a solution to these vulnerabilities.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:323");
  script_xref(name:"URL", value:"http://marc.info/?l=apache-httpd-announce&m=125755783724966&w=2");
  script_tag(name:"summary", value:"The remote host is missing an update to apache
announced via advisory MDVSA-2009:323.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.6~8.3mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
