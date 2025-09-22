# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705214");
  script_cve_id("CVE-2022-23803", "CVE-2022-23804", "CVE-2022-23946", "CVE-2022-23947");
  script_tag(name:"creation_date", value:"2022-08-23 01:00:06 +0000 (Tue, 23 Aug 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 03:12:28 +0000 (Fri, 11 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5214-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5214-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5214-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5214");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kicad");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kicad' package(s) announced via the DSA-5214-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple buffer overflows were discovered in Kicad, a suite of programs for the creation of printed circuit boards, which could result in the execution of arbitrary code if malformed Gerber/Excellon files.

For the stable distribution (bullseye), these problems have been fixed in version 5.1.9+dfsg1-1+deb11u1.

We recommend that you upgrade your kicad packages.

For the detailed security status of kicad please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kicad' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"kicad", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-demos", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ca", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-de", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-en", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-es", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-fr", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-id", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-it", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ja", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-pl", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-ru", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-doc-zh", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicad-libraries", ver:"5.1.9+dfsg1-1+deb11u1", rls:"DEB11"))) {
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
