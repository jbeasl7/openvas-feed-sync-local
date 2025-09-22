# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63410");
  script_cve_id("CVE-2008-5153", "CVE-2008-6125", "CVE-2009-0500", "CVE-2009-0502");
  script_tag(name:"creation_date", value:"2009-02-18 22:13:28 +0000 (Wed, 18 Feb 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1724-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1724-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1724-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1724");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-1724-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Moodle, an online course management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0500

It was discovered that the information stored in the log tables was not properly sanitized, which could allow attackers to inject arbitrary web code.

CVE-2009-0502

It was discovered that certain input via the 'Login as' function was not properly sanitised leading to the injection of arbitrary web script.

CVE-2008-5153

Dmitry E. Oboukhov discovered that the SpellCheker plugin creates temporary files insecurely, allowing a denial of service attack. Since the plugin was unused, it is removed in this update.

For the stable distribution (etch) these problems have been fixed in version 1.6.3-2+etch2.

For the testing (lenny) distribution these problems have been fixed in version 1.8.2.dfsg-3+lenny1.

For the unstable (sid) distribution these problems have been fixed in version 1.8.2.dfsg-4.

We recommend that you upgrade your moodle package.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.6.3-2+etch2", rls:"DEB4"))) {
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
