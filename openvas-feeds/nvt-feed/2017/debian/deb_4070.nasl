# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704070");
  script_cve_id("CVE-2017-17843", "CVE-2017-17844", "CVE-2017-17845", "CVE-2017-17846", "CVE-2017-17847", "CVE-2017-17848");
  script_tag(name:"creation_date", value:"2017-12-20 23:00:00 +0000 (Wed, 20 Dec 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-10 19:25:34 +0000 (Wed, 10 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-4070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4070-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4070-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4070");
  script_xref(name:"URL", value:"https://enigmail.net/download/other/Enigmail%20Pentest%20Report%20by%20Cure53%20-%20Excerpt.pdf");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/enigmail");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'enigmail' package(s) announced via the DSA-4070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Enigmail, an OpenPGP extension for Thunderbird, which could result in a loss of confidentiality, faked signatures, plain text leaks and denial of service. Additional information can be found under [link moved to references]

For the oldstable distribution (jessie), this problem has been fixed in version 2:1.9.9-1~deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 2:1.9.9-1~deb9u1.

We recommend that you upgrade your enigmail packages.

For the detailed security status of enigmail please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'enigmail' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"enigmail", ver:"2:1.9.9-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"enigmail", ver:"2:1.9.9-1~deb9u1", rls:"DEB9"))) {
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
