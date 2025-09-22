# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703840");
  script_cve_id("CVE-2017-3523");
  script_tag(name:"creation_date", value:"2017-05-01 22:00:00 +0000 (Mon, 01 May 2017)");
  script_version("2024-02-01T14:37:11+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:11 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-04 14:23:27 +0000 (Thu, 04 May 2017)");

  script_name("Debian: Security Advisory (DSA-3840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3840-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3840-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3840");
  script_xref(name:"URL", value:"https://www.computest.nl/advisories/CT-2017-0425_MySQL-Connector-J.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-connector-java' package(s) announced via the DSA-3840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thijs Alkemade discovered that unexpected automatic deserialisation of Java objects in the MySQL Connector/J JDBC driver may result in the execution of arbitrary code. For additional details, please refer to the advisory at [link moved to references]

For the stable distribution (jessie), this problem has been fixed in version 5.1.41-1~deb8u1.

For the upcoming stable distribution (stretch), this problem has been fixed in version 5.1.41-1.

For the unstable distribution (sid), this problem has been fixed in version 5.1.41-1.

We recommend that you upgrade your mysql-connector-java packages.");

  script_tag(name:"affected", value:"'mysql-connector-java' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmysql-java", ver:"5.1.41-1~deb8u1", rls:"DEB8"))) {
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
