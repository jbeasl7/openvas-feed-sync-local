# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56320");
  script_cve_id("CVE-2004-2161", "CVE-2004-2162");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-980-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-980-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-980");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tutos' package(s) announced via the DSA-980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joxean Koret discovered several security problems in tutos, a web-based team organization software. The Common Vulnerabilities and Exposures Project identifies the following problems:

CVE-2004-2161

An SQL injection vulnerability allows the execution of SQL commands through the link_id parameter in file_overview.php.

CVE-2004-2162

Cross-Site-Scripting vulnerabilities in the search function of the address book and in app_new.php allow the execution of web script code.

The old stable distribution (woody) does not contain tutos packages.

For the stable distribution (sarge) these problems have been fixed in version 1.1.20031017-2+1sarge1.

The unstable distribution (sid) does no longer contain tutos packages.

We recommend that you upgrade your tutos package.");

  script_tag(name:"affected", value:"'tutos' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"tutos", ver:"1.1.20031017-2+1sarge1", rls:"DEB3.1"))) {
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
