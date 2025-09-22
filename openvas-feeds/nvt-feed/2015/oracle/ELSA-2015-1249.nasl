# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123063");
  script_cve_id("CVE-2013-5704");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:53 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-1249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1249");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1249.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the ELSA-2015-1249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2.15-45.0.1]
- replace index.html with Oracle's index page oracle_index.html
- update vstring in specfile

[2.2.15-45]
- mod_proxy_balancer: add support for 'drain mode' (N) (#767130)

[2.2.15-44]
- set SSLCipherSuite to DEFAULT:!EXP:!SSLv2:!DES:!IDEA:!SEED:+3DES (#1086771)

[2.2.15-43]
- revert DirectoryMatch patch from 2.2.15-40 (#1016963)

[2.2.15-42]
- core: fix bypassing of mod_headers rules via chunked requests (CVE-2013-5704)

[2.2.15-41]
- fix compilation with older OpenSSL caused by misspelling in patch (#1162268)

[2.2.15-40]
- mod_proxy: do not mix workers shared memory during graceful restart (#1149906)
- mod_ssl: Fix SSL_CLIENT_VERIFY value when optional_no_ca and SSLSessionCache
 are used and SSL session is resumed (#1149703)
- mod_ssl: log revoked certificates at the INFO level (#1161328)
- mod_ssl: use -extensions v3_req for certificate generation (#906476)
- core: check the config file before restarting the server (#1146194)
- core: do not match files when using DirectoryMatch (#1016963)
- core: improve error message for inaccessible DocumentRoot (#987590)
- rotatelogs: improve support for localtime (#922844)
- mod_deflate: fix decompression of files larger than 4GB (#1057695)
- ab: fix integer overflow when printing stats with lot of requests (#1092419)
- ab: try all addresses instead of failing on first one when not available (#1125269)
- ab: fix read failure when targeting SSL server (#1045477)
- apachectl: support HTTPD_LANG variable from /etc/sysconfig/httpd (#963146)
- do not display 'bomb' icon for files ending with 'core' (#1069625)");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~45.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~45.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~45.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~45.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~45.0.1.el6", rls:"OracleLinux6"))) {
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
