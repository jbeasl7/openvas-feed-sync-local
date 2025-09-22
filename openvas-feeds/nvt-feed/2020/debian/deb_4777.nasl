# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704777");
  script_cve_id("CVE-2020-15999");
  script_tag(name:"creation_date", value:"2020-10-23 03:00:10 +0000 (Fri, 23 Oct 2020)");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 14:37:57 +0000 (Wed, 05 Feb 2025)");

  script_name("Debian: Security Advisory (DSA-4777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4777-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4777-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4777");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/freetype");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-4777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sergei Glazunov discovered a heap-based buffer overflow vulnerability in the handling of embedded PNG bitmaps in FreeType. Opening malformed fonts may result in denial of service or the execution of arbitrary code.

For the stable distribution (buster), this problem has been fixed in version 2.9.1-3+deb10u2.

We recommend that you upgrade your freetype packages.

For the detailed security status of freetype please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freetype2-demos", ver:"2.9.1-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freetype2-doc", ver:"2.9.1-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6", ver:"2.9.1-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-dev", ver:"2.9.1-3+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreetype6-udeb", ver:"2.9.1-3+deb10u2", rls:"DEB10"))) {
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
