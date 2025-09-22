# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68092");
  script_cve_id("CVE-2010-3091", "CVE-2010-3092", "CVE-2010-3093", "CVE-2010-3094", "CVE-2010-3685", "CVE-2010-3686");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2113-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2113-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2113-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2113");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal6' package(s) announced via the DSA-2113-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Drupal 6 a fully-featured content management framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3091

Several issues have been discovered in the OpenID module that allows malicious access to user accounts.

CVE-2010-3092

The upload module includes a potential bypass of access restrictions due to not checking letter case-sensitivity.

CVE-2010-3093

The comment module has a privilege escalation issue that allows certain users to bypass limitations.

CVE-2010-3094

Several cross-site scripting (XSS) issues have been discovered in the Action feature.

For the stable distribution (lenny), these problems have been fixed in version 6.6-3lenny6.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 6.18-1.

We recommend that you upgrade your drupal6 packages.");

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

  if(!isnull(res = isdpkgvuln(pkg:"drupal6", ver:"6.6-3lenny6", rls:"DEB5"))) {
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
