# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704748");
  script_cve_id("CVE-2020-16287", "CVE-2020-16288", "CVE-2020-16289", "CVE-2020-16290", "CVE-2020-16291", "CVE-2020-16292", "CVE-2020-16293", "CVE-2020-16294", "CVE-2020-16295", "CVE-2020-16296", "CVE-2020-16297", "CVE-2020-16298", "CVE-2020-16299", "CVE-2020-16300", "CVE-2020-16301", "CVE-2020-16302", "CVE-2020-16303", "CVE-2020-16304", "CVE-2020-16305", "CVE-2020-16306", "CVE-2020-16307", "CVE-2020-16308", "CVE-2020-16309", "CVE-2020-16310", "CVE-2020-17538");
  script_tag(name:"creation_date", value:"2020-08-27 03:00:37 +0000 (Thu, 27 Aug 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:01:14 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4748-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4748-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4748-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4748");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ghostscript");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ghostscript' package(s) announced via the DSA-4748-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Ghostscript, the GPL PostScript/PDF interpreter which could result in denial of service and potentially the execution of arbitrary code if malformed document files are processed.

For the stable distribution (buster), these problems have been fixed in version 9.27~dfsg-2+deb10u4.

We recommend that you upgrade your ghostscript packages.

For the detailed security status of ghostscript please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-dbg", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-doc", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.27~dfsg-2+deb10u4", rls:"DEB10"))) {
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
