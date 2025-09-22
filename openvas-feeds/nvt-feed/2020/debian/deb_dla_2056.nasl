# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892056");
  script_cve_id("CVE-2019-16789");
  script_tag(name:"creation_date", value:"2020-01-02 03:00:08 +0000 (Thu, 02 Jan 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 21:45:53 +0000 (Wed, 08 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-2056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-2056-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2056-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'waitress' package(s) announced via the DLA-2056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a HTTP request smuggling vulnerability in waitress, pure-Python WSGI server.

CVE-2019-16789

In Waitress through version 1.4.0, if a proxy server is used in front of waitress, an invalid request may be sent by an attacker that bypasses the front-end and is parsed differently by waitress leading to a potential for HTTP request smuggling. Specially crafted requests containing special whitespace characters in the Transfer-Encoding header would get parsed by Waitress as being a chunked request, but a front-end server would use the Content-Length instead as the Transfer-Encoding header is considered invalid due to containing invalid characters. If a front-end server does HTTP pipelining to a backend Waitress server this could lead to HTTP request splitting which may lead to potential cache poisoning or unexpected information disclosure. This issue is fixed in Waitress 1.4.1 through more strict HTTP field validation.

For Debian 8 Jessie, these problems have been fixed in version 0.8.9-2+deb8u1.

We recommend that you upgrade your waitress packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'waitress' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"python-waitress", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-waitress-doc", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-waitress", ver:"0.8.9-2+deb8u1", rls:"DEB8"))) {
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
