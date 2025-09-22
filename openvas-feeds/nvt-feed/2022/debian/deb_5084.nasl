# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705084");
  script_cve_id("CVE-2022-22589", "CVE-2022-22590", "CVE-2022-22592", "CVE-2022-22620");
  script_tag(name:"creation_date", value:"2022-02-22 02:00:06 +0000 (Tue, 22 Feb 2022)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-26 04:23:52 +0000 (Sat, 26 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-5084-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5084-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5084-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5084");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpewebkit");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpewebkit' package(s) announced via the DSA-5084-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WPE WebKit web engine:

CVE-2022-22589

Heige and Bo Qu discovered that processing a maliciously crafted mail message may lead to running arbitrary javascript.

CVE-2022-22590

Toan Pham discovered that processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-22592

Prakash discovered that processing maliciously crafted web content may prevent Content Security Policy from being enforced.

CVE-2022-22620

An anonymous researcher discovered that processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

For the stable distribution (bullseye), these problems have been fixed in version 2.34.6-1~deb11u1.

We recommend that you upgrade your wpewebkit packages.

For the detailed security status of wpewebkit please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpewebkit' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-3", ver:"2.34.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-dev", ver:"2.34.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-doc", ver:"2.34.6-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpewebkit-driver", ver:"2.34.6-1~deb11u1", rls:"DEB11"))) {
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
