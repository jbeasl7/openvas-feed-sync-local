# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833878");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-41556");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 19:38:24 +0000 (Fri, 07 Oct 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:46:19 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for lighttpd (openSUSE-SU-2022:10140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10140-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T6C6UOQL3XPIYN6MAYXR6H6PCUA7Q4N4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd'
  package(s) announced via the openSUSE-SU-2022:10140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lighttpd fixes the following issues:
  lighttpd was updated to 1.4.67:

  * Update comment about TCP_INFO on OpenBSD

  * [mod_ajp13] fix crash with bad response headers (fixes #3170)

  * [core] handle RDHUP when collecting chunked body CVE-2022-41556
       (boo#1203872)

  * [core] tweak streaming request body to backends

  * [core] handle ENOSPC with pwritev() (#3171)

  * [core] manually calculate off_t max (fixes #3171)

  * [autoconf] force large file support (#3171)

  * [multiple] quiet coverity warnings using casts

  * [meson] add license keyword to project declaration");

  script_tag(name:"affected", value:"'lighttpd' package(s) on openSUSE Backports SLE-15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debuginfo", rpm:"lighttpd-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debugsource", rpm:"lighttpd-debugsource~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi", rpm:"lighttpd-mod_authn_gssapi~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi-debuginfo", rpm:"lighttpd-mod_authn_gssapi-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap-debuginfo", rpm:"lighttpd-mod_authn_ldap-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam", rpm:"lighttpd-mod_authn_pam~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam-debuginfo", rpm:"lighttpd-mod_authn_pam-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl", rpm:"lighttpd-mod_authn_sasl~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl-debuginfo", rpm:"lighttpd-mod_authn_sasl-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet-debuginfo", rpm:"lighttpd-mod_magnet-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb", rpm:"lighttpd-mod_maxminddb~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb-debuginfo", rpm:"lighttpd-mod_maxminddb-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool", rpm:"lighttpd-mod_rrdtool~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool-debuginfo", rpm:"lighttpd-mod_rrdtool-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi", rpm:"lighttpd-mod_vhostdb_dbi~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi-debuginfo", rpm:"lighttpd-mod_vhostdb_dbi-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap", rpm:"lighttpd-mod_vhostdb_ldap~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap-debuginfo", rpm:"lighttpd-mod_vhostdb_ldap-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql", rpm:"lighttpd-mod_vhostdb_mysql~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql-debuginfo", rpm:"lighttpd-mod_vhostdb_mysql-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql", rpm:"lighttpd-mod_vhostdb_pgsql~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql-debuginfo", rpm:"lighttpd-mod_vhostdb_pgsql-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav-debuginfo", rpm:"lighttpd-mod_webdav-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debuginfo", rpm:"lighttpd-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debugsource", rpm:"lighttpd-debugsource~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi", rpm:"lighttpd-mod_authn_gssapi~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi-debuginfo", rpm:"lighttpd-mod_authn_gssapi-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap-debuginfo", rpm:"lighttpd-mod_authn_ldap-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam", rpm:"lighttpd-mod_authn_pam~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam-debuginfo", rpm:"lighttpd-mod_authn_pam-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl", rpm:"lighttpd-mod_authn_sasl~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl-debuginfo", rpm:"lighttpd-mod_authn_sasl-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet-debuginfo", rpm:"lighttpd-mod_magnet-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb", rpm:"lighttpd-mod_maxminddb~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb-debuginfo", rpm:"lighttpd-mod_maxminddb-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool", rpm:"lighttpd-mod_rrdtool~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool-debuginfo", rpm:"lighttpd-mod_rrdtool-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi", rpm:"lighttpd-mod_vhostdb_dbi~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi-debuginfo", rpm:"lighttpd-mod_vhostdb_dbi-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap", rpm:"lighttpd-mod_vhostdb_ldap~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap-debuginfo", rpm:"lighttpd-mod_vhostdb_ldap-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql", rpm:"lighttpd-mod_vhostdb_mysql~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql-debuginfo", rpm:"lighttpd-mod_vhostdb_mysql-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql", rpm:"lighttpd-mod_vhostdb_pgsql~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql-debuginfo", rpm:"lighttpd-mod_vhostdb_pgsql-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav-debuginfo", rpm:"lighttpd-mod_webdav-debuginfo~1.4.67~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);