# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120289");
  script_cve_id("CVE-2015-0228", "CVE-2015-0253", "CVE-2015-3183", "CVE-2015-3185");
  script_tag(name:"creation_date", value:"2015-09-08 11:22:54 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-579)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-579");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-579.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd24' package(s) announced via the ALAS-2015-579 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that in httpd 2.4, the internal API function ap_some_auth_required() could incorrectly indicate that a request was authenticated even when no authentication was used. An httpd module using this API function could consequently allow access that should have been denied. (CVE-2015-3185)

Multiple flaws were found in the way httpd parsed HTTP requests and responses using chunked transfer encoding. A remote attacker could use these flaws to create a specially crafted request, which httpd would decode differently from an HTTP proxy software in front of it, possibly leading to HTTP request smuggling attacks. (CVE-2015-3183)

A NULL pointer dereference flaw was found in the way httpd generated certain error responses. A remote attacker could possibly use this flaw crash the httpd child process using a request that triggers a certain HTTP error. (CVE-2015-0253)

A denial of service flaw was found in the way the mod_lua httpd module processed certain WebSocket Ping requests. A remote attacker could send a specially crafted WebSocket Ping packet that would cause the httpd child process to crash. (CVE-2015-0228)");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd24", rpm:"httpd24~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-debuginfo", rpm:"httpd24-debuginfo~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-devel", rpm:"httpd24-devel~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-manual", rpm:"httpd24-manual~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-tools", rpm:"httpd24-tools~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ldap", rpm:"mod24_ldap~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_proxy_html", rpm:"mod24_proxy_html~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_session", rpm:"mod24_session~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ssl", rpm:"mod24_ssl~2.4.16~1.62.amzn1", rls:"AMAZON"))) {
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
