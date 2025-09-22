# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70558");
  script_cve_id("CVE-2011-4103");
  script_tag(name:"creation_date", value:"2012-02-11 07:29:22 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2344-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2344-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2344");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django-piston' package(s) announced via the DSA-2344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Piston framework can deserializes untrusted YAML and Pickle data, leading to remote code execution (CVE-2011-4103).

The old stable distribution (lenny) does not contain a python-django-piston package.

For the stable distribution (squeeze), this problem has been fixed in version 0.2.2-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 0.2.2-2.

We recommend that you upgrade your python-django-piston packages.");

  script_tag(name:"affected", value:"'python-django-piston' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django-piston", ver:"0.2.2-1+squeeze1", rls:"DEB6"))) {
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
