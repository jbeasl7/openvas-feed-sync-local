# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705028");
  script_cve_id("CVE-2021-44118", "CVE-2021-44120", "CVE-2021-44122", "CVE-2021-44123");
  script_tag(name:"creation_date", value:"2021-12-23 10:04:56 +0000 (Thu, 23 Dec 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-02 16:15:11 +0000 (Wed, 02 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5028-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5028-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5028-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5028");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/spip");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DSA-5028-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SPIP, a website engine for publishing, would allow a malicious user to perform cross-site scripting and SQL injection attacks, or execute arbitrary code.

For the oldstable distribution (buster), this problem has been fixed in version 3.2.4-1+deb10u5.

For the stable distribution (bullseye), this problem has been fixed in version 3.2.11-3+deb11u1.

We recommend that you upgrade your spip packages.

For the detailed security status of spip please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 10, Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.4-1+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.11-3+deb11u1", rls:"DEB11"))) {
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
