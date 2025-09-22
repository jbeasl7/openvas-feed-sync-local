# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704127");
  script_cve_id("CVE-2017-12867", "CVE-2017-12869", "CVE-2017-12873", "CVE-2017-12874", "CVE-2017-18121", "CVE-2017-18122", "CVE-2018-6519", "CVE-2018-6521", "CVE-2018-7644");
  script_tag(name:"creation_date", value:"2018-03-01 23:00:00 +0000 (Thu, 01 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 16:36:21 +0000 (Thu, 15 Feb 2018)");

  script_name("Debian: Security Advisory (DSA-4127-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4127-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4127-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4127");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/simplesamlphp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'simplesamlphp' package(s) announced via the DSA-4127-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in SimpleSAMLphp, a framework for authentication, primarily via the SAML protocol.

CVE-2017-12867

Attackers with access to a secret token could extend its validity period by manipulating the prepended time offset.

CVE-2017-12869

When using the multiauth module, attackers can bypass authentication context restrictions and use any authentication source defined in the config.

CVE-2017-12873

Defensive measures have been taken to prevent the administrator from misconfiguring persistent NameIDs to avoid identifier clash. (Affects Debian 8 Jessie only.)

CVE-2017-12874

The InfoCard module could accept incorrectly signed XML messages in rare occasions.

CVE-2017-18121

The consentAdmin module was vulnerable to a Cross-Site Scripting attack, allowing an attacker to craft links that could execute arbitrary JavaScript code in the victim's browser.

CVE-2017-18122

The (deprecated) SAML 1.1 implementation would regard as valid any unsigned SAML response containing more than one signed assertion, provided that the signature of at least one of the assertions was valid, allowing an attacker that could obtain a valid signed assertion from an IdP to impersonate users from that IdP.

CVE-2018-6519

Regular expression denial of service when parsing extraordinarily long timestamps.

CVE-2018-6521

Change sqlauth module MySQL charset from utf8 to utf8mb to prevent theoretical query truncation that could allow remote attackers to bypass intended access restrictions

CVE-2018-7644

Critical signature validation vulnerability.

For the oldstable distribution (jessie), these problems have been fixed in version 1.13.1-2+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1.14.11-1+deb9u1.

We recommend that you upgrade your simplesamlphp packages.

For the detailed security status of simplesamlphp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'simplesamlphp' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.13.1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.14.11-1+deb9u1", rls:"DEB9"))) {
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
