# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882521");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-19 05:26:52 +0200 (Tue, 19 Jul 2016)");
  script_cve_id("CVE-2016-5387");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:40:00 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for httpd CESA-2016:1422 centos7");
  script_tag(name:"summary", value:"Check the version of httpd");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP
Server, a powerful, efficient, and extensible web server.

Security Fix(es):

  * It was discovered that httpd used the value of the Proxy header from HTTP
requests to initialize the HTTP_PROXY environment variable for CGI scripts,
which in turn was incorrectly used by certain HTTP client implementations
to configure the proxy for outgoing HTTP requests. A remote attacker could
possibly use this flaw to redirect HTTP requests performed by a CGI script
to an attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the Proxy
request header to scripts via the HTTP_PROXY environment variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.

Bug Fix(es):

  * In a caching proxy configuration, the mod_cache module would treat
content as stale if the Expires header changed when refreshing a cached
response. As a consequence, an origin server returning content without a
fixed Expires header would not be treated as cacheable. The mod_cache
module has been fixed to ignore changes in the Expires header when
refreshing content. As a result, such content is now cacheable, improving
performance and reducing load at the origin server. (BZ#1347648)

  * The HTTP status code 451 'Unavailable For Legal Reasons' was not usable
in the httpd configuration. As a consequence, modules such as mod_rewrite
could not be configured to return a 451 error if required for legal
purposes. The 451 status code has been added to the list of available error
codes, and modules can now be configured to return a 451 error if required.
(BZ#1353269)

4. Solution:

For details on how to apply this update, which includes the changes
described in this advisory, refer to the linked article.

After installing the updated packages, the httpd daemon will be restarted
automatically.

5. Bugs fixed:

1347648 - Apache can not cache content if Expires header is modified
1353269 - Support sending http 451 status code from RewriteRule
1353755 - CVE-2016-5387 Apache HTTPD: sets environmental variable based on user supplied Proxy request header

6. Package List:

Red Hat Enterprise Linux Client Optional (v. 7):

Source:
httpd-2.4.6-40.el7_2.4.src.rpm

noarch:
httpd-manual-2.4.6-40.el7_2.4.noarch.rpm

x86_64:
httpd-2.4.6-40.el7_2.4.x86_64.rpm
httpd-debuginfo-2.4.6-40.el7_2.4.x86_64.rpm
httpd-devel-2.4.6-40.el7_2.4.x86_64.rpm
httpd- ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"httpd on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2016:1422");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-July/021979.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ldap", rpm:"mod_ldap~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_proxy_html", rpm:"mod_proxy_html~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~40.el7.centos.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
