# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704607");
  script_cve_id("CVE-2019-16239");
  script_tag(name:"creation_date", value:"2020-01-21 04:00:04 +0000 (Tue, 21 Jan 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-17 15:56:46 +0000 (Tue, 17 Sep 2019)");

  script_name("Debian: Security Advisory (DSA-4607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4607-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4607-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4607");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openconnect");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openconnect' package(s) announced via the DSA-4607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lukas Kupczyk reported a vulnerability in the handling of chunked HTTP in openconnect, an open client for Cisco AnyConnect, Pulse and GlobalProtect VPN. A malicious HTTP server (after having accepted its identity certificate), can provide bogus chunk lengths for chunked HTTP encoding and cause a heap-based buffer overflow.

For the oldstable distribution (stretch), this problem has been fixed in version 7.08-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 8.02-1+deb10u1.

We recommend that you upgrade your openconnect packages.

For the detailed security status of openconnect please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openconnect' package(s) on Debian 9, Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenconnect-dev", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openconnect", ver:"8.02-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenconnect-dev", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenconnect5-dbg", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openconnect", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openconnect-dbg", ver:"7.08-1+deb9u1", rls:"DEB9"))) {
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
