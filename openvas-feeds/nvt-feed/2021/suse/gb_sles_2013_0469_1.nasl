# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0469.1");
  script_cve_id("CVE-2007-6750", "CVE-2011-1473", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0883", "CVE-2012-2687", "CVE-2012-4557");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0469-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130469-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2013:0469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Apache2 LTSS roll-up update for SUSE Linux Enterprise 10 SP3 LTSS fixes the following security issues and bugs:

 * CVE-2012-4557: Denial of Service via special requests in mod_proxy_ajp
 * CVE-2012-0883: improper LD_LIBRARY_PATH handling
 * CVE-2012-2687: filename escaping problem
 * CVE-2012-0031: Fixed a scoreboard corruption (shared mem segment) by child causes crash of privileged parent
(invalid free()) during shutdown.
 * CVE-2012-0053: Fixed an issue in error responses that could expose 'httpOnly' cookies when no custom ErrorDocument is specified for status code 400'.
 * The SSL configuration template has been adjusted not to suggested weak ciphers
 *

 CVE-2007-6750: The 'mod_reqtimeout' module was backported from Apache 2.2.21 to help mitigate the
'Slowloris' Denial of Service attack.

 You need to enable the 'mod_reqtimeout' module in your existing apache configuration to make it effective,
e.g. in the APACHE_MODULES line in /etc/sysconfig/apache2.

 * CVE-2011-3639, CVE-2011-3368, CVE-2011-4317: This update also includes several fixes for a mod_proxy reverse exposure via RewriteRule or ProxyPassMatch directives.
 * CVE-2011-1473: Fixed the SSL renegotiation DoS by disabling renegotiation by default.
 * CVE-2011-3607: Integer overflow in ap_pregsub function resulting in a heap based buffer overflow could potentially allow local attackers to gain privileges

Additionally, some non-security bugs have been fixed which are listed in the changelog file.

Security Issue references:

 * CVE-2012-4557
>
 * CVE-2012-2687
>
 * CVE-2012-0883
>
 * CVE-2012-0021
>");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-devel", rpm:"apache2-devel~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.3~16.32.45.1", rls:"SLES10.0SP3"))) {
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
