# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892813");
  script_cve_id("CVE-2021-33829", "CVE-2021-37695");
  script_tag(name:"creation_date", value:"2021-11-10 02:00:12 +0000 (Wed, 10 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 20:14:53 +0000 (Thu, 10 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-2813-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2813-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2813-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ckeditor");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ckeditor' package(s) announced via the DLA-2813-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CKEditor, an open source WYSIWYG HTML editor with rich content support, which can be embedded into web pages, had two vulnerabilities as follows:

CVE-2021-33829

A cross-site scripting (XSS) vulnerability in the HTML Data Processor in CKEditor 4 allows remote attackers to inject executable JavaScript code through a crafted comment because --!> is mishandled.

CVE-2021-37695

A potential vulnerability has been discovered in CKEditor 4 Fake Objects package. The vulnerability allowed to inject malformed Fake Objects HTML, which could result in executing JavaScript code.

For Debian 9 stretch, these problems have been fixed in version 4.5.7+dfsg-2+deb9u1.

We recommend that you upgrade your ckeditor packages.

For the detailed security status of ckeditor please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ckeditor' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ckeditor", ver:"4.5.7+dfsg-2+deb9u1", rls:"DEB9"))) {
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
