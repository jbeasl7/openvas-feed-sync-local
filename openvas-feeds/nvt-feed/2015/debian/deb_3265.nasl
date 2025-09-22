# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703265");
  script_cve_id("CVE-2014-2681", "CVE-2014-2682", "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685", "CVE-2014-4914", "CVE-2014-8088", "CVE-2014-8089", "CVE-2015-3154");
  script_tag(name:"creation_date", value:"2015-05-19 22:00:00 +0000 (Tue, 19 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-20 15:04:53 +0000 (Thu, 20 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3265-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3265-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3265");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zendframework' package(s) announced via the DSA-3265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Zend Framework, a PHP framework. Except for CVE-2015-3154, all these issues were already fixed in the version initially shipped with Jessie.

CVE-2014-2681

Lukas Reschke reported a lack of protection against XML External Entity injection attacks in some functions. This fix extends the incomplete one from CVE-2012-5657.

CVE-2014-2682

Lukas Reschke reported a failure to consider that the libxml_disable_entity_loader setting is shared among threads in the PHP-FPM case. This fix extends the incomplete one from CVE-2012-5657.

CVE-2014-2683

Lukas Reschke reported a lack of protection against XML Entity Expansion attacks in some functions. This fix extends the incomplete one from CVE-2012-6532.

CVE-2014-2684

Christian Mainka and Vladislav Mladenov from the Ruhr-University Bochum reported an error in the consumer's verify method that lead to acceptance of wrongly sourced tokens.

CVE-2014-2685

Christian Mainka and Vladislav Mladenov from the Ruhr-University Bochum reported a specification violation in which signing of a single parameter is incorrectly considered sufficient.

CVE-2014-4914

Cassiano Dal Pizzol discovered that the implementation of the ORDER BY SQL statement in Zend_Db_Select contains a potential SQL injection when the query string passed contains parentheses.

CVE-2014-8088

Yury Dyachenko at Positive Research Center identified potential XML eXternal Entity injection vectors due to insecure usage of PHP's DOM extension.

CVE-2014-8089

Jonas Sandstrom discovered an SQL injection vector when manually quoting value for sqlsrv extension, using null byte.

CVE-2015-3154

Filippo Tessarotto and Maks3w reported potential CRLF injection attacks in mail and HTTP headers.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.11.13-1.1+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 1.12.9+dfsg-2+deb8u1.

For the testing distribution (stretch), these problems will be fixed in version 1.12.12+dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 1.12.12+dfsg-1.

We recommend that you upgrade your zendframework packages.");

  script_tag(name:"affected", value:"'zendframework' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"zendframework", ver:"1.11.13-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zendframework-bin", ver:"1.11.13-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zendframework-resources", ver:"1.11.13-1.1+deb7u1", rls:"DEB7"))) {
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
