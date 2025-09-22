# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704960");
  script_cve_id("CVE-2021-39240", "CVE-2021-39241", "CVE-2021-39242");
  script_tag(name:"creation_date", value:"2021-08-18 03:00:09 +0000 (Wed, 18 Aug 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-25 13:33:20 +0000 (Wed, 25 Aug 2021)");

  script_name("Debian: Security Advisory (DSA-4960-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-4960-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4960-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4960");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/haproxy");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'haproxy' package(s) announced via the DSA-4960-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in HAProxy, a fast and reliable load balancing reverse proxy, which can result in HTTP request smuggling. By carefully crafting HTTP/2 requests, it is possible to smuggle another HTTP request to the backend selected by the HTTP/2 request. With certain configurations, it allows an attacker to send an HTTP request to a backend, circumventing the backend selection logic.

Known workarounds are to disable HTTP/2 and set 'tune.h2.max-concurrent-streams' to 0 in the global section.

global tune.h2.max-concurrent-streams 0

For the stable distribution (bullseye), these problems have been fixed in version 2.2.9-2+deb11u1.

We recommend that you upgrade your haproxy packages.

For the detailed security status of haproxy please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'haproxy' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"haproxy", ver:"2.2.9-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"haproxy-doc", ver:"2.2.9-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-haproxy", ver:"2.2.9-2+deb11u1", rls:"DEB11"))) {
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
