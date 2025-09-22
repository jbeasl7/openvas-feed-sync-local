# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704996");
  script_cve_id("CVE-2021-30818", "CVE-2021-30823", "CVE-2021-30846", "CVE-2021-30851", "CVE-2021-30884", "CVE-2021-30888", "CVE-2021-30889", "CVE-2021-42762", "CVE-2021-45481", "CVE-2021-45483");
  script_tag(name:"creation_date", value:"2021-10-30 01:00:06 +0000 (Sat, 30 Oct 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 18:55:23 +0000 (Tue, 02 Nov 2021)");

  script_name("Debian: Security Advisory (DSA-4996-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-4996-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4996-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4996");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpewebkit");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpewebkit' package(s) announced via the DSA-4996-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the wpewebkit web engine:

CVE-2021-30846

Sergei Glazunov discovered that processing maliciously crafted web content may lead to arbitrary code execution

CVE-2021-30851

Samuel Gross discovered that processing maliciously crafted web content may lead to code execution

CVE-2021-42762

An anonymous reporter discovered a limited Bubblewrap sandbox bypass that allows a sandboxed process to trick host processes into thinking the sandboxed process is not confined.

For the stable distribution (bullseye), these problems have been fixed in version 2.34.1-1~deb11u1.

We recommend that you upgrade your wpewebkit packages.

For the detailed security status of wpewebkit please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpewebkit' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-3", ver:"2.34.1-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-dev", ver:"2.34.1-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-doc", ver:"2.34.1-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpewebkit-driver", ver:"2.34.1-1~deb11u1", rls:"DEB11"))) {
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
