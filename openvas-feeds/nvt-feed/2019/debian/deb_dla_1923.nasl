# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891923");
  script_cve_id("CVE-2015-3908", "CVE-2015-6240", "CVE-2018-10875", "CVE-2019-10156");
  script_tag(name:"creation_date", value:"2019-09-17 02:00:16 +0000 (Tue, 17 Sep 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-29 18:20:46 +0000 (Fri, 29 May 2020)");

  script_name("Debian: Security Advisory (DLA-1923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1923-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1923-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ansible' package(s) announced via the DLA-1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Ansible, a configuration management, deployment, and task execution system.

CVE-2015-3908

A potential man-in-the-middle attack associated with insusfficient X.509 certificate verification. Ansible did not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.

CVE-2015-6240

A symlink attack that allows local users to escape a restricted environment (chroot or jail) via a symlink attack.

CVE-2018-10875

A fix potential arbitrary code execution resulting from reading ansible.cfg from a world-writable current working directory. This condition now causes ansible to emit a warning and ignore the ansible.cfg in the world-writable current working directory.

CVE-2019-10156

Information disclosure through unexpected variable substitution.

For Debian 8 Jessie, these problems have been fixed in version 1.7.2+dfsg-2+deb8u2.

We recommend that you upgrade your ansible packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ansible' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ansible-doc", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ansible-fireball", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ansible-node-fireball", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
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
