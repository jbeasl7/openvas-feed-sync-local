# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2016");
  script_cve_id("CVE-2010-2250", "CVE-2010-2471", "CVE-2010-2472", "CVE-2010-2473");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-13 16:16:29 +0000 (Wed, 13 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-2016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2016-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2016-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2016");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal6' package(s) announced via the DSA-2016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities (SA-CORE-2010-001) have been discovered in drupal6, a fully-featured content management framework.

Installation cross site scripting

A user-supplied value is directly output during installation allowing a malicious user to craft a URL and perform a cross-site scripting attack. The exploit can only be conducted on sites not yet installed.

Open redirection

The API function drupal_goto() is susceptible to a phishing attack. An attacker could formulate a redirect in a way that gets the Drupal site to send the user to an arbitrarily provided URL. No user submitted data will be sent to that URL.

Locale module cross site scripting

Locale module and dependent contributed modules do not sanitize the display of language codes, native and English language names properly. While these usually come from a preselected list, arbitrary administrator input is allowed. This vulnerability is mitigated by the fact that the attacker must have a role with the 'administer languages' permission.

Blocked user session regeneration

Under certain circumstances, a user with an open session that is blocked can maintain his/her session on the Drupal site, despite being blocked.

For the stable distribution (lenny), these problems have been fixed in version 6.6-3lenny5.

For the unstable distribution (sid), these problems have been fixed in version 6.16-1, and will migrate to the testing distribution (squeeze) shortly.

We recommend that you upgrade your drupal6 package.");

  script_tag(name:"affected", value:"'drupal6' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"drupal6", ver:"6.6-3lenny5", rls:"DEB5"))) {
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
