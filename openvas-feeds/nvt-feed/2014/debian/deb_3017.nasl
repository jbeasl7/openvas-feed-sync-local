# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703017");
  script_cve_id("CVE-2014-4172");
  script_tag(name:"creation_date", value:"2014-09-01 22:00:00 +0000 (Mon, 01 Sep 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-12 15:18:54 +0000 (Wed, 12 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3017-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3017-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3017");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-cas' package(s) announced via the DSA-3017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marvin S. Addison discovered that Jasig phpCAS, a PHP library for the CAS authentication protocol, did not encode tickets before adding them to an URL, creating a possibility for cross site scripting.

For the stable distribution (wheezy), this problem has been fixed in version 1.3.1-4+deb7u1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your php-cas packages.");

  script_tag(name:"affected", value:"'php-cas' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-cas", ver:"1.3.1-4+deb7u1", rls:"DEB7"))) {
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
