# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704764");
  script_cve_id("CVE-2019-20917", "CVE-2020-25269");
  script_tag(name:"creation_date", value:"2020-09-20 03:00:07 +0000 (Sun, 20 Sep 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-15 14:33:23 +0000 (Tue, 15 Sep 2020)");

  script_name("Debian: Security Advisory (DSA-4764-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4764-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4764-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4764");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/inspircd");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'inspircd' package(s) announced via the DSA-4764-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues were discovered in the pgsql and mysql modules of the InspIRCd IRC daemon, which could result in denial of service.

For the stable distribution (buster), these problems have been fixed in version 2.0.27-1+deb10u1.

We recommend that you upgrade your inspircd packages.

For the detailed security status of inspircd please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'inspircd' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"2.0.27-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.27-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inspircd-dev", ver:"2.0.27-1+deb10u1", rls:"DEB10"))) {
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
