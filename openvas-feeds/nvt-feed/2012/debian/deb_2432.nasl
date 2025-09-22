# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71236");
  script_cve_id("CVE-2012-1152");
  script_tag(name:"creation_date", value:"2012-04-30 11:54:15 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2432-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2432-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2432-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2432");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libyaml-libyaml-perl' package(s) announced via the DSA-2432-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dominic Hargreaves and Niko Tyni discovered two format string vulnerabilities in YAML::LibYAML, a Perl interface to the libyaml library.

For the stable distribution (squeeze), this problem has been fixed in version 0.33-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 0.38-2.

We recommend that you upgrade your libyaml-libyaml-perl packages.");

  script_tag(name:"affected", value:"'libyaml-libyaml-perl' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libyaml-libyaml-perl", ver:"0.33-1+squeeze1", rls:"DEB6"))) {
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
