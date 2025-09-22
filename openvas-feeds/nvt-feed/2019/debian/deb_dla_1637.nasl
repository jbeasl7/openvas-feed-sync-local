# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891637");
  script_cve_id("CVE-2019-3462");
  script_tag(name:"creation_date", value:"2019-01-21 23:00:00 +0000 (Mon, 21 Jan 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-20 19:04:14 +0000 (Wed, 20 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-1637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1637-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1637-1");
  script_xref(name:"URL", value:"http://cdn-fastly.deb.debian.org/debian-security");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-doc_1.0.9.8.5_all.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-doc_1.0.9.8.5_all.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg4.12_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-inst1.5_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/libapt-pkg-dev_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-utils_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/debian-security/pool/updates/main/a/apt/apt-transport-https_1.0.9.8.5_i386.deb");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DLA-1637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Justicz discovered a vulnerability in APT, the high level package manager. The code handling HTTP redirects in the HTTP transport method doesn't properly sanitize fields transmitted over the wire. This vulnerability could be used by an attacker located as a man-in-the-middle between APT and a mirror to inject malicious content in the HTTP connection. This content could then be recognized as a valid package by APT and used later for code execution with root privileges on the target machine.

Since the vulnerability is present in the package manager itself, it is recommended to disable redirects in order to prevent exploitation during this upgrade only, using:

apt -o Acquire::http::AllowRedirect=false update apt -o Acquire::http::AllowRedirect=false upgrade

This is known to break some proxies when used against security.debian.org. If that happens, people can switch their security APT source to use:

deb [link moved to references] jessie/updates main

For Debian 8 Jessie, this problem has been fixed in version 1.0.9.8.5.

We recommend that you upgrade your apt packages.

Specific upgrade instructions:

If upgrading using APT without redirect is not possible in your situation, you can manually download the files (using wget/curl) for your architecture using the URL provided below, verifying that the hashes match. Then you can install them using dpkg -i.

Architecture independent files:

[link moved to references] Size/SHA256 checksum: 301106 47df9567e45fadcd2a56c0fd3d514d8136f2f206aa7baa47405c6fcb94824ab6 [link moved to references] Size/SHA256 checksum: 750506 ce79b2ef272716b8da11f3fd0497ce0b7ee69c9c66d01669e8abbbfdde5e6256

amd64 architecture:

[link moved to references] Size/SHA256 checksum: 792126 295d9c69854a4cfbcb46001b09b853f5a098a04c986fc5ae01a0124c1c27e6bd [link moved to references] Size/SHA256 checksum: 168896 f9615532b1577b3d1455fa51839ce91765f2860eb3a6810fb5e0de0c87253030 [link moved to references] Size/SHA256 checksum: 1109308 4078748632abc19836d045f80f9d6933326065ca1d47367909a0cf7f29e7dfe8 [link moved to references] Size/SHA256 checksum: 192950 09ef86d178977163b8cf0081d638d74e0a90c805dd77750c1d91354b6840b032 [link moved to references] Size/SHA256 checksum: 368396 87c55d9ccadcabd59674873c221357c774020c116afd978fb9df6d2d0303abf2 [link moved to references] Size/SHA256 checksum: 137230 f5a17422fd319ff5f6e3ea9a9e87d2508861830120125484130da8c1fd479df2

armel architecture:

[link moved to references] Size/SHA256 checksum: 717002 80fe021d87f2444abdd7c5491e7a4bf9ab9cb2b8e6fa72d308905f4e0aad60d4 [link moved to references] Size/SHA256 checksum: 166784 046fb962fa214c5d6acfb7344e7719f8c4898d87bf29ed3cd2115e3f6cdd14e9 [link moved to references] Size/SHA256 checksum: 1067404 f9a257d6aace1f222633e0432abf1d6946bad9dbd0ca18dccb288d50f17b895f [link moved to references] Size/SHA256 checksum: 193768 4cb226f55132a68a2f5db925ada6147aaf052adb02301fb45fb0c2d1cfce36f0 [link moved to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apt", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-doc", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-transport-https", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-utils", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-inst1.5", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-dev", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-doc", ver:"1.0.9.8.5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg4.12", ver:"1.0.9.8.5", rls:"DEB8"))) {
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
