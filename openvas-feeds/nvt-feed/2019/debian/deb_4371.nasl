# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704371");
  script_cve_id("CVE-2019-3462");
  script_tag(name:"creation_date", value:"2019-01-21 23:00:00 +0000 (Mon, 21 Jan 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-20 19:04:14 +0000 (Wed, 20 Feb 2019)");

  script_name("Debian: Security Advisory (DSA-4371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4371-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4371-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4371");
  script_xref(name:"URL", value:"http://cdn-fastly.deb.debian.org/debian-security");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.dsc");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9.tar.xz");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-doc_1.4.9_all.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-doc_1.4.9_all.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_amd64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_arm64.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_armel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_armhf.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_i386.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mips64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mips.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_mipsel.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-transport-https_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt-utils_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/apt_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-inst2.0_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg-dev_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"http://security.debian.org/pool/updates/main/a/apt/libapt-pkg5.0_1.4.9_ppc64el.deb");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DSA-4371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Justicz discovered a vulnerability in APT, the high level package manager. The code handling HTTP redirects in the HTTP transport method doesn't properly sanitize fields transmitted over the wire. This vulnerability could be used by an attacker located as a man-in-the-middle between APT and a mirror to inject malicious content in the HTTP connection. This content could then be recognized as a valid package by APT and used later for code execution with root privileges on the target machine.

Since the vulnerability is present in the package manager itself, it is recommended to disable redirects in order to prevent exploitation during this upgrade only, using:

apt -o Acquire::http::AllowRedirect=false update apt -o Acquire::http::AllowRedirect=false upgrade

This is known to break some proxies when used against security.debian.org. If that happens, people can switch their security APT source to use:

deb [link moved to references] stable/updates main

For the stable distribution (stretch), this problem has been fixed in version 1.4.9.

We recommend that you upgrade your apt packages.

Specific upgrade instructions:

If upgrading using APT without redirect is not possible in your situation, you can manually download the files (using wget/curl) for your architecture using the URL provided below, verifying that the hashes match. Then you can install them using dpkg -i.

Source archives:

[link moved to references] Size/SHA256 checksum: 2549 986d98b00caac809341f65acb3d14321d645ce8e87e411c26c66bf149a10dfea [link moved to references] Size/SHA256 checksum: 2079572 d4d65e7c84da86f3e6dcc933bba46a08db429c9d933b667c864f5c0e880bac0d

Architecture independent files:

[link moved to references] Size/SHA256 checksum: 365094 8880640591f64ab7b798f0421d18cba618512ca61ed7c44fbbbb6140423551d5 [link moved to references] Size/SHA256 checksum: 1004234 42f4c5945c4c471c3985db1cec7adcac516cc21a497a438f3ea0a2bfa7ffe036

amd64 architecture:

[link moved to references] Size/SHA256 checksum: 170820 c8c4366d1912ff8223615891397a78b44f313b0a2f15a970a82abe48460490cb [link moved to references] Size/SHA256 checksum: 409958 fb227d1c4615197a6263e7312851ac3601d946221cfd85f20427a15ab9658d15 [link moved to references] Size/SHA256 checksum: 1231594 dddf4ff686845b82c6c778a70f1f607d0bb9f8aa43f2fb7983db4ff1a55f5fae [link moved to references] Size/SHA256 checksum: 192382 a099c57d20b3e55d224433b7a1ee972f6fdb79911322882d6e6f6a383862a57d [link moved to references] Size/SHA256 checksum: 235220 cfb0a03ecd22aba066d97e75d4d00d791c7a3aceb2e5ec4fbee7176389717404 [link moved to references] Size/SHA256 checksum: 916448 03281e3d1382826d5989c12c77a9b27f5f752b0f6aa28b524a2df193f7296e0b

arm64 architecture:

[link moved to references] Size/SHA256 checksum: 167674 6635e174290f89555a2eb9cbc083b1fa566b2cd65318212c8c760b87bfb2c544 [link moved to references] Size/SHA256 checksum: 401136 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apt", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-doc", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-transport-https", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apt-utils", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-inst2.0", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-dev", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg-doc", ver:"1.4.9", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapt-pkg5.0", ver:"1.4.9", rls:"DEB9"))) {
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
