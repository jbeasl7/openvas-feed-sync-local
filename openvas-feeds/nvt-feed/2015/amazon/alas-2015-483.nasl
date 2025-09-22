# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120323");
  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-3583", "CVE-2014-8109");
  script_tag(name:"creation_date", value:"2015-09-08 11:23:32 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-483");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-483.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd24' package(s) announced via the ALAS-2015-483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mod_lua.c in the mod_lua module in the Apache HTTP Server 2.3.x and 2.4.x through 2.4.10 does not support an httpd configuration in which the same Lua authorization provider is used with different arguments within different contexts, which allows remote attackers to bypass intended access restrictions in opportunistic circumstances by leveraging multiple Require directives, as demonstrated by a configuration that specifies authorization for one group to access a certain directory, and authorization for a second group to access a second directory. (CVE-2014-8109)

A flaw was found in the way httpd handled HTTP Trailer headers when processing requests using chunked encoding. A malicious client could use Trailer headers to set additional HTTP headers after header processing was performed by other modules. This could, for example, lead to a bypass of header restrictions defined with mod_headers. (CVE-2013-5704)

A NULL pointer dereference flaw was found in the way the mod_cache httpd module handled Content-Type headers. A malicious HTTP server could cause the httpd child process to crash when the Apache HTTP server was configured to proxy to a server with caching enabled. (CVE-2014-3581)

The handle_headers function in mod_proxy_fcgi.c in the mod_proxy_fcgi module in the Apache HTTP Server 2.4.10 allows remote FastCGI servers to cause a denial of service (buffer over-read and daemon crash) via long response headers. (CVE-2014-3583)");

  script_tag(name:"affected", value:"'httpd24' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"httpd24", rpm:"httpd24~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-debuginfo", rpm:"httpd24-debuginfo~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-devel", rpm:"httpd24-devel~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-manual", rpm:"httpd24-manual~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-tools", rpm:"httpd24-tools~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ldap", rpm:"mod24_ldap~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_proxy_html", rpm:"mod24_proxy_html~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_session", rpm:"mod24_session~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ssl", rpm:"mod24_ssl~2.4.10~15.58.amzn1", rls:"AMAZON"))) {
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
