# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64950");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-28 19:09:13 +0200 (Mon, 28 Sep 2009)");
  script_cve_id("CVE-2009-3094", "CVE-2009-3095");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Mandrake Security Advisory MDVSA-2009:240 (apache)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|mes5|2\.0)");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in apache:

The ap_proxy_ftp_handler function in modules/proxy/proxy_ftp.c in
the mod_proxy_ftp module in the Apache HTTP Server 2.0.63 and 2.2.13
allows remote FTP servers to cause a denial of service (NULL pointer
dereference and child process crash) via a malformed reply to an EPSV
command (CVE-2009-3094).

The mod_proxy_ftp module in the Apache HTTP Server allows remote
attackers to bypass intended access restrictions and send arbitrary
commands to an FTP server via vectors related to the embedding of these
commands in the Authorization HTTP header, as demonstrated by a certain
module in VulnDisco Pack Professional 8.11.  NOTE: as of 20090903,
this disclosure has no actionable information. However, because the
VulnDisco Pack author is a reliable researcher, the issue is being
assigned a CVE identifier for tracking purposes (CVE-2009-3095).

This update provides a solution to these vulnerabilities.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0, Multi Network Firewall 2.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:240");
  script_tag(name:"summary", value:"The remote host is missing an update to apache
announced via advisory MDVSA-2009:240.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.8~6.6mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.9~12.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.11~10.5mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-common", rpm:"apache2-common~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-manual", rpm:"apache2-manual~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_cache", rpm:"apache2-mod_cache~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_dav", rpm:"apache2-mod_dav~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_deflate", rpm:"apache2-mod_deflate~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_disk_cache", rpm:"apache2-mod_disk_cache~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_file_cache", rpm:"apache2-mod_file_cache~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_ldap", rpm:"apache2-mod_ldap~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_mem_cache", rpm:"apache2-mod_mem_cache~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_proxy", rpm:"apache2-mod_proxy~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_ssl", rpm:"apache2-mod_ssl~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-modules", rpm:"apache2-modules~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-source", rpm:"apache2-source~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr0", rpm:"libapr0~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64apr0", rpm:"lib64apr0~2.0.48~6.23.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.3~1.8.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.9~12.4mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-common", rpm:"apache2-common~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-manual", rpm:"apache2-manual~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_cache", rpm:"apache2-mod_cache~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_dav", rpm:"apache2-mod_dav~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_deflate", rpm:"apache2-mod_deflate~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_disk_cache", rpm:"apache2-mod_disk_cache~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_file_cache", rpm:"apache2-mod_file_cache~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_ldap", rpm:"apache2-mod_ldap~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_mem_cache", rpm:"apache2-mod_mem_cache~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_proxy", rpm:"apache2-mod_proxy~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-mod_ssl", rpm:"apache2-mod_ssl~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-modules", rpm:"apache2-modules~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"apache2-source", rpm:"apache2-source~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libapr0", rpm:"libapr0~2.0.48~6.23.C30mdk", rls:"MNDK_2.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
