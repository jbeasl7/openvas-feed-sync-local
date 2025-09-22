# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703889");
  script_cve_id("CVE-2017-1000376");
  script_tag(name:"creation_date", value:"2017-06-18 22:00:00 +0000 (Sun, 18 Jun 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-05 17:58:37 +0000 (Wed, 05 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3889-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3889-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3889-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3889");
  script_xref(name:"URL", value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libffi' package(s) announced via the DSA-3889-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libffi, a library used to call code written in one language from code written in a different language, was enforcing an executable stack on the i386 architecture. While this might not be considered a vulnerability by itself, this could be leveraged when exploiting other vulnerabilities, like for example the stack clash class of vulnerabilities discovered by Qualys Research Labs. For the full details, please refer to their advisory published at: [link moved to references]

For the oldstable distribution (jessie), this problem has been fixed in version 3.1-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 3.2.1-4.

For the testing distribution (buster), this problem has been fixed in version 3.2.1-4.

For the unstable distribution (sid), this problem has been fixed in version 3.2.1-4.

We recommend that you upgrade your libffi packages.");

  script_tag(name:"affected", value:"'libffi' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libffi-dev", ver:"3.1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libffi6", ver:"3.1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libffi6-dbg", ver:"3.1-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libffi6-udeb", ver:"3.1-2+deb8u1", rls:"DEB8"))) {
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
