# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892954");
  script_cve_id("CVE-2022-23607");
  script_tag(name:"creation_date", value:"2022-03-19 02:00:05 +0000 (Sat, 19 Mar 2022)");
  script_version("2024-02-01T14:37:12+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:12 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 18:58:09 +0000 (Fri, 26 Jan 2024)");

  script_name("Debian: Security Advisory (DLA-2954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2954-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2954-1");
  script_xref(name:"URL", value:"https://example.com");
  script_xref(name:"URL", value:"http://cloudstorageprovider.com");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-treq' package(s) announced via the DLA-2954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an information disclosure issue in python-treq, a high-level library/API for making HTTP requests using the Twisted network programming library. HTTP cookies were not bound to a single domain and were instead sent to every domain.

CVE-2022-23607

treq is an HTTP library inspired by requests but written on top of Twisted's Agents. Treq's request methods (`treq.get`, `treq.post`, etc.) and `treq.client.HTTPClient` constructor accept cookies as a dictionary. Such cookies are not bound to a single domain, and are therefore sent to *every* domain ('supercookies'). This can potentially cause sensitive information to leak upon an HTTP redirect to a different domain., e.g. should `[link moved to references]` redirect to `[link moved to references]` the latter will receive the cookie `session`. Treq 2021.1.0 and later bind cookies given to request methods (`treq.request`, `treq.get`, `HTTPClient.request`, `HTTPClient.get`, etc.) to the origin of the *url* parameter. Users are advised to upgrade. For users unable to upgrade Instead of passing a dictionary as the *cookies* argument, pass a `http.cookiejar.CookieJar` instance with properly domain- and scheme-scoped cookies in it.

For Debian 9 Stretch, these problems have been fixed in version 15.1.0-1+deb9u1.

We recommend that you upgrade your python-treq packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'python-treq' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-treq", ver:"15.1.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-treq-doc", ver:"15.1.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-treq", ver:"15.1.0-1+deb9u1", rls:"DEB9"))) {
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
