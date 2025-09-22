# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704811");
  script_cve_id("CVE-2020-26217");
  script_tag(name:"creation_date", value:"2020-12-16 04:00:14 +0000 (Wed, 16 Dec 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-01 16:04:38 +0000 (Tue, 01 Dec 2020)");

  script_name("Debian: Security Advisory (DSA-4811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4811-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4811-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4811");
  script_xref(name:"URL", value:"https://github.com/x-stream/xstream/security/advisories/GHSA-mw36-7c6c-q4q2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxstream-java");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxstream-java' package(s) announced via the DSA-4811-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the default blacklist of XStream, a Java library to serialise objects to XML and back again, was vulnerable to the execution of arbitrary shell commands by manipulating the processed input stream.

For additional defense-in-depth it is recommended to switch to the whitelist approach of XStream's security framework. For additional information please refer to [link moved to references]

For the stable distribution (buster), this problem has been fixed in version 1.4.11.1-1+deb10u1.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1+deb10u1", rls:"DEB10"))) {
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
