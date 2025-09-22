# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703793");
  script_cve_id("CVE-2016-6252", "CVE-2017-2616");
  script_tag(name:"creation_date", value:"2017-02-23 23:00:00 +0000 (Thu, 23 Feb 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-21 13:49:05 +0000 (Fri, 21 Sep 2018)");

  script_name("Debian: Security Advisory (DSA-3793-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3793-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3793-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3793");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'shadow' package(s) announced via the DSA-3793-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the shadow suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-6252

An integer overflow vulnerability was discovered, potentially allowing a local user to escalate privileges via crafted input to the newuidmap utility.

CVE-2017-2616

Tobias Stoeckmann discovered that su does not properly handle clearing a child PID. A local attacker can take advantage of this flaw to send SIGKILL to other processes with root privileges, resulting in denial of service.

For the stable distribution (jessie), these problems have been fixed in version 1:4.2-3+deb8u3.

We recommend that you upgrade your shadow packages.");

  script_tag(name:"affected", value:"'shadow' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"login", ver:"1:4.2-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passwd", ver:"1:4.2-3+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uidmap", ver:"1:4.2-3+deb8u3", rls:"DEB8"))) {
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
