# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.178");
  script_cve_id("CVE-2015-2688", "CVE-2015-2689");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 21:16:30 +0000 (Fri, 31 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-178-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/DLA-178-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DLA-178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered and fixed in Tor, a connection-based low-latency anonymous communication system.

o Jowr discovered that very high DNS query load on a relay could trigger an assertion error.

o A relay could crash with an assertion error if a buffer of exactly the wrong layout was passed to buf_pullup() at exactly the wrong time.

o When sending the address of the chosen rendezvous point to a hidden service clients were leaking to the hidden service they were on a little-endian or big-endian systems.

Furthermore, this update disables support for SSLv3 in Tor. All versions of OpenSSL in use with Tor today support TLS 1.0 or later.

Additionally, this release updates the geoIP database used by Tor as well as the list of directory authority servers, which Tor clients use to bootstrap and trust to sign the Tor directory consensus document.

For Debian 6 Squeeze, these issues have been fixed in tor version 0.2.4.26-1~deb6u1");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.2.4.26-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.4.26-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.4.26-1~deb6u1", rls:"DEB6"))) {
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
