# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703841");
  script_cve_id("CVE-2017-7957");
  script_tag(name:"creation_date", value:"2017-05-01 22:00:00 +0000 (Mon, 01 May 2017)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-23 17:54:30 +0000 (Fri, 23 May 2025)");

  script_name("Debian: Security Advisory (DSA-3841-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3841-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3841-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3841");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DSA-3841-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that XStream, a Java library to serialise objects to XML and back again, was suspectible to denial of service during unmarshalling.

For the stable distribution (jessie), this problem has been fixed in version 1.4.7-2+deb8u2.

For the upcoming stable distribution (stretch), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.4.9-2.

We recommend that you upgrade your libxstream-java packages.");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.7-2+deb8u2", rls:"DEB8"))) {
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
