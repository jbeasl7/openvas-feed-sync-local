# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705170");
  script_cve_id("CVE-2021-22959", "CVE-2021-22960", "CVE-2021-44531", "CVE-2021-44532", "CVE-2021-44533", "CVE-2022-21824");
  script_tag(name:"creation_date", value:"2022-06-29 01:00:12 +0000 (Wed, 29 Jun 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-08 16:41:38 +0000 (Tue, 08 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-5170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5170-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5170-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5170");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/nodejs");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nodejs' package(s) announced via the DSA-5170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Node.js, which could result in HTTP request smuggling, a bypass of certificate verification or prototype pollution.

For the stable distribution (bullseye), these problems have been fixed in version 12.22.12~dfsg-1~deb11u1.

We recommend that you upgrade your nodejs packages.

For the detailed security status of nodejs please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'nodejs' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"12.22.12~dfsg-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.12~dfsg-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.12~dfsg-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs-doc", ver:"12.22.12~dfsg-1~deb11u1", rls:"DEB11"))) {
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
