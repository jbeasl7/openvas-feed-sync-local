# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704817");
  script_cve_id("CVE-2020-28948", "CVE-2020-28949");
  script_tag(name:"creation_date", value:"2020-12-20 04:00:07 +0000 (Sun, 20 Dec 2020)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-02 14:28:16 +0000 (Wed, 02 Dec 2020)");

  script_name("Debian: Security Advisory (DSA-4817-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4817-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4817-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4817");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php-pear");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-pear' package(s) announced via the DSA-4817-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in the PEAR Archive_Tar package for handling tar files in PHP, potentially allowing a remote attacker to execute arbitrary code or overwrite files.

For the stable distribution (buster), these problems have been fixed in version 1:1.10.6+submodules+notgz-1.1+deb10u1.

We recommend that you upgrade your php-pear packages.

For the detailed security status of php-pear please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php-pear' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"1:1.10.6+submodules+notgz-1.1+deb10u1", rls:"DEB10"))) {
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
