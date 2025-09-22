# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892685");
  script_cve_id("CVE-2021-28651", "CVE-2021-28652", "CVE-2021-31806", "CVE-2021-31807", "CVE-2021-31808", "CVE-2021-33620");
  script_tag(name:"creation_date", value:"2021-06-15 03:00:11 +0000 (Tue, 15 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 16:40:31 +0000 (Wed, 09 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-2685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2685-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2685-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/squid3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squid3' package(s) announced via the DLA-2685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Squid, a proxy caching server.

CVE-2021-28651

Due to a buffer-management bug, it allows a denial of service. When resolving a request with the urn: scheme, the parser leaks a small amount of memory. However, there is an unspecified attack methodology that can easily trigger a large amount of memory consumption.

CVE-2021-28652

Due to incorrect parser validation, it allows a Denial of Service attack against the Cache Manager API. This allows a trusted client to trigger memory leaks that. over time, lead to a Denial of Service via an unspecified short query string. This attack is limited to clients with Cache Manager API access privilege.

CVE-2021-31806

Due to a memory-management bug, it is vulnerable to a Denial of Service attack (against all clients using the proxy) via HTTP Range request processing.

CVE-2021-31807

An integer overflow problem allows a remote server to achieve Denial of Service when delivering responses to HTTP Range requests. The issue trigger is a header that can be expected to exist in HTTP traffic without any malicious intent.

CVE-2021-31808

Due to an input-validation bug, it is vulnerable to a Denial of Service attack (against all clients using the proxy). A client sends an HTTP Range request to trigger this.

CVE-2021-33620

Remote servers to cause a denial of service (affecting availability to all clients) via an HTTP response. The issue trigger is a header that can be expected to exist in HTTP traffic without any malicious intent by the server.

For Debian 9 stretch, these problems have been fixed in version 3.5.23-5+deb9u7.

We recommend that you upgrade your squid3 packages.

For the detailed security status of squid3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-dbg", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.5.23-5+deb9u7", rls:"DEB9"))) {
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
