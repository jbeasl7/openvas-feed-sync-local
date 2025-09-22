# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72566");
  script_cve_id("CVE-2012-4505");
  script_tag(name:"creation_date", value:"2012-11-16 08:15:03 +0000 (Fri, 16 Nov 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2571-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2571-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2571-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2571");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libproxy' package(s) announced via the DSA-2571-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Red Hat Security Response Team discovered that libproxy, a library for automatic proxy configuration management, applied insufficient validation to the Content-Length header sent by a server providing a proxy.pac file. Such remote server could trigger an integer overflow and consequently overflow an in-memory buffer.

For the stable distribution (squeeze), this problem has been fixed in version 0.3.1-2+squeeze1.

For the testing distribution (wheezy), and the unstable distribution (sid), this problem has been fixed in version 0.3.1-5.1.

We recommend that you upgrade your libproxy packages.");

  script_tag(name:"affected", value:"'libproxy' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libproxy-dev", ver:"0.3.1-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libproxy-tools", ver:"0.3.1-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libproxy0", ver:"0.3.1-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-libproxy", ver:"0.3.1-2+squeeze1", rls:"DEB6"))) {
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
