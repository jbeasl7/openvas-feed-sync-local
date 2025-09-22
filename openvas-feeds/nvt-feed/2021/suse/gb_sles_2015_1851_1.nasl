# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1851.1");
  script_cve_id("CVE-2014-8111", "CVE-2015-3183", "CVE-2015-3185", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-07-21 16:52:00 +0000 (Tue, 21 Jul 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1851-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1851-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151851-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/444878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949771");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-October/001653.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2015:1851-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Apache2 webserver was updated to fix several issues:

Security issues fixed:
- The chunked transfer coding implementation in the Apache HTTP Server
 did not properly parse chunk headers, which allowed remote attackers to
 conduct HTTP request smuggling attacks via a crafted request, related
 to mishandling of large chunk-size values and invalid chunk-extension
 characters in modules/http/http_filters.c. [bsc#938728, CVE-2015-3183]
- The LOGJAM security issue was addressed by: [bnc#931723 CVE-2015-4000]
 * changing the SSLCipherSuite cipherstring to disable export cipher
 suites and deploy Ephemeral Elliptic-Curve Diffie-Hellman (ECDHE)
 ciphers.
 * Adjust 'gensslcert' script to generate a strong and unique Diffie
 Hellman Group and append it to the server certificate file.
- The ap_some_auth_required function in server/request.c in the Apache
 HTTP Server 2.4.x did not consider that a Require directive may be
 associated with an authorization setting rather than an authentication
 setting, which allowed remote attackers to bypass intended access
 restrictions in opportunistic circumstances by leveraging the presence
 of a module that relies on the 2.2 API behavior.
 [bnc#938723 bnc#939516 CVE-2015-3185]
- Tomcat mod_jk information leak due to incorrect JkMount/JkUnmount
 directives processing [bnc#927845 CVE-2014-8111]

Other bugs fixed:
- Now provides a suse_maintenance_mmn_# [bnc#915666].
- Hardcoded modules in the %files [bnc#444878].
- Fixed the IfModule directive around SSLSessionCache [bnc#911159].
- allow only TCP ports in Yast2 firewall files [bnc#931002]
- fixed a regression when some LDAP searches or comparisons might be done
 with the wrong credentials when a backend connection is reused
 [bnc#930228]
- Fixed split-logfile2 script [bnc#869790]
- remove the changed MODULE_MAGIC_NUMBER_MINOR from which confuses
 modules the way that they expect functionality that our apache does
 not provide [bnc#915666]
- gensslcert: CN now defaults to `hostname -f` [bnc#949766], fix
 help [bnc#949771]");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.10~14.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.10~14.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.10~14.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_kerb", rpm:"apache2-mod_auth_kerb~5.4~2.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_jk", rpm:"apache2-mod_jk~1.2.40~2.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_security2", rpm:"apache2-mod_security2~2.8.0~3.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.10~14.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.10~14.10.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.10~14.10.1", rls:"SLES12.0"))) {
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
