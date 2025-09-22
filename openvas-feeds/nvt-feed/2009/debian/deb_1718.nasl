# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63334");
  script_cve_id("CVE-2009-0126");
  script_tag(name:"creation_date", value:"2009-02-10 14:52:40 +0000 (Tue, 10 Feb 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1718-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1718-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1718-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1718");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'boinc' package(s) announced via the DSA-1718-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the core client for the BOINC distributed computing infrastructure performs incorrect validation of the return values of OpenSSL's RSA functions.

For the stable distribution (etch), this problem has been fixed in version 5.4.11-4+etch1.

For the upcoming stable distribution (lenny), this problem has been fixed in version 6.2.14-3.

For the unstable distribution (sid), this problem has been fixed in version 6.2.14-3.

We recommend that you upgrade your boinc packages.");

  script_tag(name:"affected", value:"'boinc' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"boinc-client", ver:"5.4.11-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"boinc-dev", ver:"5.4.11-4+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"boinc-manager", ver:"5.4.11-4+etch1", rls:"DEB4"))) {
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
