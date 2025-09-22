# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53532");
  script_cve_id("CVE-2005-0256");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-705-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-705-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-705");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wu-ftpd' package(s) announced via the DSA-705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several denial of service conditions have been discovered in wu-ftpd, the popular FTP daemon. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-0256

Adam Zabrocki discovered a denial of service condition in wu-ftpd that could be exploited by a remote user and cause the server to slow down by resource exhaustion.

CAN-2003-0854

Georgi Guninski discovered that /bin/ls may be called from within wu-ftpd in a way that will result in large memory consumption and hence slow down the server.

For the stable distribution (woody) these problems have been fixed in version 2.6.2-3woody5.

For the unstable distribution (sid) these problems have been fixed in version 2.6.2-19.

We recommend that you upgrade your wu-ftpd package.");

  script_tag(name:"affected", value:"'wu-ftpd' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wu-ftpd", ver:"2.6.2-3woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wu-ftpd-academ", ver:"2.6.2-3woody5", rls:"DEB3.0"))) {
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
