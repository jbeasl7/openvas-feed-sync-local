# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122868");
  script_cve_id("CVE-2013-5704", "CVE-2014-3581");
  script_tag(name:"creation_date", value:"2016-02-05 12:01:37 +0000 (Fri, 05 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1972)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1972");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1972.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd24-httpd' package(s) announced via the ELSA-2014-1972 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.4.6-22.0.1.el6]
- remove enable-tlsv1x-thunks to fit openssl 1.x api
- replace index.html with Oracle's index page oracle_index.html
- update vstring in specfile

[2.4.6-22]
- Remove mod_proxy_fcgi fix for heap-based buffer overflow,
 httpd-2.4.6 is not affected (CVE-2014-3583)

[2.4.6-21]
- mod_proxy_wstunnel: Fix the use of SSL with the 'wss:' scheme (#1141950)

[2.4.6-20]
- core: fix bypassing of mod_headers rules via chunked requests (CVE-2013-5704)
- mod_cache: fix NULL pointer dereference on empty Content-Type (CVE-2014-3581)
- mod_proxy_fcgi: fix heap-based buffer overflow (CVE-2014-3583)

[2.4.6-19]
- mod_cgid: add security fix for CVE-2014-0231
- mod_proxy: add security fix for CVE-2014-0117
- mod_deflate: add security fix for CVE-2014-0118
- mod_status: add security fix for CVE-2014-0226
- mod_cache: add secutiry fix for CVE-2013-4352");

  script_tag(name:"affected", value:"'httpd24-httpd' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd24-httpd", rpm:"httpd24-httpd~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-httpd-devel", rpm:"httpd24-httpd-devel~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-httpd-manual", rpm:"httpd24-httpd-manual~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-httpd-tools", rpm:"httpd24-httpd-tools~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-mod_ldap", rpm:"httpd24-mod_ldap~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-mod_proxy_html", rpm:"httpd24-mod_proxy_html~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-mod_session", rpm:"httpd24-mod_session~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-mod_ssl", rpm:"httpd24-mod_ssl~2.4.6~22.0.1.el6", rls:"OracleLinux6"))) {
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
