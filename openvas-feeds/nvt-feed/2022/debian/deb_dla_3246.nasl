# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893246");
  script_cve_id("CVE-2022-29167");
  script_tag(name:"creation_date", value:"2022-12-23 10:21:51 +0000 (Fri, 23 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 16:58:31 +0000 (Mon, 16 May 2022)");

  script_name("Debian: Security Advisory (DLA-3246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3246-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3246-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-hawk' package(s) announced via the DLA-3246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in Hawk, an HTTP authentication scheme. Hawk used a regular expression to parse `Host` HTTP headers which was subject to regular expression DoS attack. Each added character in the attacker's input increased the computation time exponentially.

CVE-2022-29167

Hawk is an HTTP authentication scheme providing mechanisms for making authenticated HTTP requests with partial cryptographic verification of the request and response, covering the HTTP method, request URI, host, and optionally the request payload. Hawk used a regular expression to parse `Host` HTTP header (`Hawk.utils.parseHost()`), which was subject to regular expression DoS attack - meaning each added character in the attacker's input increases the computation time exponentially. `parseHost()` was patched in `9.0.1` to use built-in `URL` class to parse hostname instead. `Hawk.authenticate()` accepts `options` argument. If that contains `host` and `port`, those would be used instead of a call to `utils.parseHost()`.

For Debian 10 Buster, this problem has been fixed in version 6.0.1+dfsg-1+deb10u1.

We recommend that you upgrade your node-hawk packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-hawk' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-hawk", ver:"6.0.1+dfsg-1+deb10u1", rls:"DEB10"))) {
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
