# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123705");
  script_cve_id("CVE-2008-0455", "CVE-2012-2687", "CVE-2012-4557");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:28 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0512)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0512");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0512.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the ELSA-2013-0512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2.15-26.0.1.el6]
- replace index.html with Oracle's index page oracle_index.html
 update vstring in specfile

[2.2.15-26]
- htcacheclean: exit with code 4 also for 'restart' action (#805810)

[2.2.15-25]
- htcacheclean: exit with code 4 if nonprivileged user runs initscript (#805810)
- rotatelogs: omit the second arg when invoking a post-rotate program (#876923)

[2.2.15-24]
- mod_ssl: improved patch for mod_nss fallback (w/mharmsen, #805720)

[2.2.15-23]
- mod_log_config: fix cookie parsing substring mismatch (#867268)

[2.2.15-22]
- mod_cache: fix header merging for 304 case, thanks to Roy Badami (#868283)
- mod_cache: fix handling of 304 responses (#868253)

[2.2.15-21]
- mod_proxy_ajp: ignore flushing if headers have not been sent (#853160)
- mod_proxy_ajp: do not mark worker in error state when one request
 timeouts (#864317)
- mod_ssl: do not run post script if all files are already created (#752618)

[2.2.15-20]
- add htcacheclean init script (Jan Kaluza, #805810)

[2.2.15-19]
- mod_ssl: fall back on another module's proxy hook if mod_ssl proxy
 is not configured. (#805720)

[2.2.15-18]
- add security fix for CVE-2012-2687 (#850794)

[2.2.15-17]
- mod_proxy: allow change BalancerMember state in web interface (#748400)
- mod_proxy: Tone down 'worker [URL] used by another worker' warning (#787247)
- mod_proxy: add support for 'failonstatus' option (#824571)
- mod_proxy: avoid DNS lookup on hostname from request URI if
 ProxyRemote* is configured (#837086)
- rotatelogs: create files even if they are empty (#757739)
- rotatelogs: option to rotate files into a custom location (#757735)
- rotatelogs: add support for -L option (#838493)
- fix handling of long chunk-line (#842376)
- add server aliases to 'httpd -S' output (#833092)
- omit %posttrans daemon restart if
 /etc/sysconfig/httpd-disable-posttrans exists (#833064)
- mod_ldap: treat LDAP_UNAVAILABLE as a transient error (#829689)
- ab: fix double free when SSL request fails in verbose mode (#837613)
- mod_cache: do not cache partial results (#822587)
- mod_ldap: add LDAPReferrals directive alias (#796958)
- mod_ssl: add _userID DN variable suffix for NID_userId (#842375)
- mod_ssl: fix test for missing decrypted private keys, and ensure that
 the keypair matches (#848954)
- mod_authnz_ldap: set AUTHORIZE_* variables in LDAP authorization (#828896)
- relax checks for status-line validity (#853348)

[2.2.15-16]
- add security fixes for CVE-2011-4317, CVE-2012-0053, CVE-2012-0031,
 CVE-2011-3607 (#787599)
- obviates fix for CVE-2011-3638, patch removed");

  script_tag(name:"affected", value:"'httpd' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~26.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~26.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~26.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~26.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~26.0.1.el6", rls:"OracleLinux6"))) {
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
