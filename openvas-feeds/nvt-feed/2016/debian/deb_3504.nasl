# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703504");
  script_cve_id("CVE-2016-2510");
  script_tag(name:"creation_date", value:"2016-03-08 07:07:51 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-12 18:06:17 +0000 (Tue, 12 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3504-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3504-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3504");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bsh' package(s) announced via the DSA-3504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alvaro Munoz and Christian Schneider discovered that BeanShell, an embeddable Java source interpreter, could be leveraged to execute arbitrary commands: applications including BeanShell in their classpath are vulnerable to this flaw if they deserialize data from an untrusted source.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.0b4-12+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 2.0b4-15+deb8u1.

For the testing distribution (stretch) and unstable distribution (sid), this problem has been fixed in version 2.0b4-16.

We recommend that you upgrade your bsh packages.");

  script_tag(name:"affected", value:"'bsh' package(s) on Debian 7, Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bsh", ver:"2.0b4-12+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsh-doc", ver:"2.0b4-12+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsh-gcj", ver:"2.0b4-12+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsh-src", ver:"2.0b4-12+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"bsh", ver:"2.0b4-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsh-doc", ver:"2.0b4-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bsh-src", ver:"2.0b4-15+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libbsh-java", ver:"2.0b4-15+deb8u1", rls:"DEB8"))) {
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
