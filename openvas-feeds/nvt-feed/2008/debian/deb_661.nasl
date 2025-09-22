# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53539");
  script_cve_id("CVE-2005-0017", "CVE-2005-0018");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-661-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-661-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-661-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-661");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'f2c' package(s) announced via the DSA-661-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan McMahill noticed that our advisory DSA 661-1 did not correct the multiple insecure files problem, hence, this update. For completeness below is the original advisory text:

Javier Fernandez-Sanguino Pena from the Debian Security Audit project discovered that f2c and fc, which are both part of the f2c package, a fortran 77 to C/C++ translator, open temporary files insecurely and are hence vulnerable to a symlink attack. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2005-0017

Multiple insecure temporary files in the f2c translator.

CAN-2005-0018

Two insecure temporary files in the f2 shell script.

For the stable distribution (woody) and all others including testing this problem has been fixed in version 20010821-3.2.

We recommend that you upgrade your f2c package.");

  script_tag(name:"affected", value:"'f2c' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"f2c", ver:"20010821-3.2", rls:"DEB3.0"))) {
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
