# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892571");
  script_cve_id("CVE-2015-8011", "CVE-2017-9214", "CVE-2018-17204", "CVE-2018-17206", "CVE-2020-27827", "CVE-2020-35498");
  script_tag(name:"creation_date", value:"2021-02-20 04:00:17 +0000 (Sat, 20 Feb 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-17 18:22:41 +0000 (Wed, 17 Feb 2021)");

  script_name("Debian: Security Advisory (DLA-2571-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2571-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2571-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openvswitch");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openvswitch' package(s) announced via the DLA-2571-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in openvswitch, a production quality, multilayer, software-based, Ethernet virtual switch.

CVE-2020-35498

Denial of service attacks, in which crafted network packets could cause the packet lookup to ignore network header fields from layers 3 and 4. The crafted network packet is an ordinary IPv4 or IPv6 packet with Ethernet padding length above 255 bytes. This causes the packet sanity check to abort parsing header fields after layer 2.

CVE-2020-27827

Denial of service attacks using crafted LLDP packets.

CVE-2018-17206

Buffer over-read issue during BUNDLE action decoding.

CVE-2018-17204

Assertion failure due to not validating information (group type and command) in OF1.5 decoder.

CVE-2017-9214

Buffer over-read that is caused by an unsigned integer underflow.

CVE-2015-8011

Buffer overflow in the lldp_decode function in daemon/protocols/lldp.c in lldpd before 0.8.0 allows remote attackers to cause a denial of service (daemon crash) and possibly execute arbitrary code via vectors involving large management addresses and TLV boundaries.

For Debian 9 stretch, these problems have been fixed in version 2.6.10-0+deb9u1. This version is a new upstream point release.

We recommend that you upgrade your openvswitch packages.

For the detailed security status of openvswitch please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dbg", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-dev", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-ipsec", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-pki", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-switch", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-test", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-testcontroller", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-vtep", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-central", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-common", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-controller-vtep", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-docker", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovn-host", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-openvswitch", ver:"2.6.10-0+deb9u1", rls:"DEB9"))) {
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
