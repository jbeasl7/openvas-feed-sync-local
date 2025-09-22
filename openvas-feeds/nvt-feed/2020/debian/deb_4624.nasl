# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704624");
  script_cve_id("CVE-2017-1000159", "CVE-2019-1010006", "CVE-2019-11459");
  script_tag(name:"creation_date", value:"2020-02-15 04:00:08 +0000 (Sat, 15 Feb 2020)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:07:20 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-4624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4624-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4624-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4624");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/evince");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'evince' package(s) announced via the DSA-4624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in evince, a simple multi-page document viewer.

CVE-2017-1000159

Tobias Mueller reported that the DVI exporter in evince is susceptible to a command injection vulnerability via specially crafted filenames.

CVE-2019-11459

Andy Nguyen reported that the tiff_document_render() and tiff_document_get_thumbnail() functions in the TIFF document backend did not handle errors from TIFFReadRGBAImageOriented(), leading to disclosure of uninitialized memory when processing TIFF image files.

CVE-2019-1010006

A buffer overflow vulnerability in the tiff backend could lead to denial of service, or potentially the execution of arbitrary code if a specially crafted PDF file is opened.

For the oldstable distribution (stretch), these problems have been fixed in version 3.22.1-3+deb9u2.

For the stable distribution (buster), these problems have been fixed in version 3.30.2-3+deb10u1. The stable distribution is only affected by CVE-2019-11459.

We recommend that you upgrade your evince packages.

For the detailed security status of evince please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'evince' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"browser-plugin-evince", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-common", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"evince-gtk", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-evince-3.0", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevdocument3-4", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevince-dev", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libevview3-3", ver:"3.22.1-3+deb9u2", rls:"DEB9"))) {
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
