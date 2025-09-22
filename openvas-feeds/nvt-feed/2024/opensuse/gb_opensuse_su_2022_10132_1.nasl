# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833002");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-37797");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-15 04:08:26 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:20:35 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for lighttpd (openSUSE-SU-2022:10132-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10132-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ATUOJQDWIRALBMVI5GOSOGPZP5AWVAZF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd'
  package(s) announced via the openSUSE-SU-2022:10132-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lighttpd fixes the following issues:
  lighttpd was updated to 1.4.66:

  * a number of bug fixes

  * Fix HTTP/2 downloads  = 4GiB

  * Fix SIGUSR1 graceful restart with TLS

  * further bug fixes

  * CVE-2022-37797: null pointer dereference in mod_wstunnel, possibly a
       remotely triggerable crash (boo#1203358)

  * In an upcoming release the TLS modules will default to using stronger,
       modern chiphers and will default to allow client preference in selecting
       ciphers. CipherString =
       EECDH+AESGCM:AES256+EECDH:CHACHA20:SHA256:!SHA384, Options
       =  -ServerPreference
       old defaults: CipherString =  HIGH, Options =
        ServerPreference

  * A number of TLS options are how deprecated and will be removed in a
       future release:  ssl.honor-cipher-order  ssl.dh-file
       ssl.ec-curve  ssl.disable-client-renegotiation  ssl.use-sslv2
       ssl.use-sslv3 The replacement option is ssl.openssl.ssl-conf-cmd, but
       lighttpd defaults should be preferred

  * A number of modules are now deprecated and will be removed in a future
       release: mod_evasive, mod_secdownload, mod_uploadprogress, mod_usertrack
       can be replaced by mod_magnet and a few lines of lua.
  update to 1.4.65:

  * WebSockets over HTTP/2

  * RFC 8441 Bootstrapping WebSockets with HTTP/2

  * HTTP/2 PRIORITY_UPDATE

  * RFC 9218 Extensible Prioritization Scheme for HTTP

  * prefix/suffix conditions in lighttpd.conf

  * mod_webdav safe partial-PUT

  * webdav.opts += (partial-put-copy-modify =  enable)

  * mod_accesslog option: accesslog.escaping = json

  * mod_deflate libdeflate build option

  * speed up request body uploads via HTTP/2

  * Behavior Changes

  * change default server.max-keep-alive-requests = 1000 to adjust

  * to increasing HTTP/2 usage and to web2/web3 application usage

  * (prior default was 100)

  * mod_status HTML now includes HTTP/2 control stream id 0 in the output

  * which contains aggregate counts for the HTTP/2 connection");

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

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debuginfo", rpm:"lighttpd-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-debugsource", rpm:"lighttpd-debugsource~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi", rpm:"lighttpd-mod_authn_gssapi~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_gssapi-debuginfo", rpm:"lighttpd-mod_authn_gssapi-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap-debuginfo", rpm:"lighttpd-mod_authn_ldap-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam", rpm:"lighttpd-mod_authn_pam~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_pam-debuginfo", rpm:"lighttpd-mod_authn_pam-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl", rpm:"lighttpd-mod_authn_sasl~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_sasl-debuginfo", rpm:"lighttpd-mod_authn_sasl-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet-debuginfo", rpm:"lighttpd-mod_magnet-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb", rpm:"lighttpd-mod_maxminddb~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_maxminddb-debuginfo", rpm:"lighttpd-mod_maxminddb-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool", rpm:"lighttpd-mod_rrdtool~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_rrdtool-debuginfo", rpm:"lighttpd-mod_rrdtool-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi", rpm:"lighttpd-mod_vhostdb_dbi~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_dbi-debuginfo", rpm:"lighttpd-mod_vhostdb_dbi-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap", rpm:"lighttpd-mod_vhostdb_ldap~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_ldap-debuginfo", rpm:"lighttpd-mod_vhostdb_ldap-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql", rpm:"lighttpd-mod_vhostdb_mysql~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_mysql-debuginfo", rpm:"lighttpd-mod_vhostdb_mysql-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql", rpm:"lighttpd-mod_vhostdb_pgsql~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_vhostdb_pgsql-debuginfo", rpm:"lighttpd-mod_vhostdb_pgsql-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav-debuginfo", rpm:"lighttpd-mod_webdav-debuginfo~1.4.66~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
