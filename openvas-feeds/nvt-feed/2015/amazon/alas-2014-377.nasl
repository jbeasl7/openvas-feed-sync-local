# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120576");
  script_cve_id("CVE-2014-2681", "CVE-2014-2682", "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685");
  script_tag(name:"creation_date", value:"2015-09-08 11:29:54 +0000 (Tue, 08 Sep 2015)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-377)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-377");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-377.html");
  script_xref(name:"URL", value:"https://openid.net/specs/openid-authentication-2_0.html#positive_assertions");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-ZendFramework' package(s) announced via the ALAS-2014-377 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The GenericConsumer class in the Consumer component in ZendOpenId before 2.0.2 and the Zend_OpenId_Consumer class in Zend Framework 1 before 1.12.4 violate the OpenID 2.0 protocol by ensuring only that at least one field is signed, which allows remote attackers to bypass authentication by leveraging an assertion from an OpenID provider.

XML eXternal Entity (XXE) and XML Entity Expansion (XEE) flaws were discovered in the Zend Framework. An attacker could use these flaws to cause a denial of service, access files accessible to the server process, or possibly perform other more advanced XML External Entity (XXE) attacks.

Using the Consumer component of ZendOpenId (or Zend_OpenId in ZF1), it is possible to login using an arbitrary OpenID account (without knowing any secret information) by using a malicious OpenID Provider. That means OpenID it is possible to login using arbitrary OpenID Identity (MyOpenID, Google, etc), which are not under the control of our own OpenID Provider. Thus, we are able to impersonate any OpenID Identity against the framework.

Moreover, the Consumer accepts OpenID tokens with arbitrary signed elements. The framework does not check if, for example, both openid.claimed_id and openid.endpoint_url are signed. It is just sufficient to sign one parameter. According to [link moved to references] at least op_endpoint, return_to, response_nonce, assoc_handle, and, if present in the response, claimed_id and identity, must be signed.");

  script_tag(name:"affected", value:"'php-ZendFramework' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Auth-Adapter-Ldap", rpm:"php-ZendFramework-Auth-Adapter-Ldap~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Apc", rpm:"php-ZendFramework-Cache-Backend-Apc~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Libmemcached", rpm:"php-ZendFramework-Cache-Backend-Libmemcached~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Cache-Backend-Memcached", rpm:"php-ZendFramework-Cache-Backend-Memcached~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Captcha", rpm:"php-ZendFramework-Captcha~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Mysqli", rpm:"php-ZendFramework-Db-Adapter-Mysqli~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo", rpm:"php-ZendFramework-Db-Adapter-Pdo~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mssql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mssql~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Mysql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Mysql~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Db-Adapter-Pdo-Pgsql", rpm:"php-ZendFramework-Db-Adapter-Pdo-Pgsql~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Dojo", rpm:"php-ZendFramework-Dojo~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Feed", rpm:"php-ZendFramework-Feed~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Ldap", rpm:"php-ZendFramework-Ldap~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Pdf", rpm:"php-ZendFramework-Pdf~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Search-Lucene", rpm:"php-ZendFramework-Search-Lucene~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Serializer-Adapter-Igbinary", rpm:"php-ZendFramework-Serializer-Adapter-Igbinary~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Services", rpm:"php-ZendFramework-Services~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-Soap", rpm:"php-ZendFramework-Soap~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-demos", rpm:"php-ZendFramework-demos~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-extras", rpm:"php-ZendFramework-extras~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework-full", rpm:"php-ZendFramework-full~1.12.5~1.8.amzn1", rls:"AMAZON"))) {
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
