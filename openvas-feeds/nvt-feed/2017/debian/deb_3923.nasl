# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703923");
  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");
  script_tag(name:"creation_date", value:"2017-07-31 22:00:00 +0000 (Mon, 31 Jul 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-25 15:20:55 +0000 (Fri, 25 May 2018)");

  script_name("Debian: Security Advisory (DSA-3923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3923-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3923-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3923");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freerdp' package(s) announced via the DSA-3923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tyler Bohan of Talos discovered that FreeRDP, a free implementation of the Remote Desktop Protocol (RDP), contained several vulnerabilities that allowed a malicious remote server or a man-in-the-middle to either cause a DoS by forcibly terminating the client, or execute arbitrary code on the client side.

For the oldstable distribution (jessie), these problems have been fixed in version 1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1.

For the stable distribution (stretch), these problems have been fixed in version 1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 1.1.0~git20140921.1.440916e+dfsg1-14.

We recommend that you upgrade your freerdp packages.");

  script_tag(name:"affected", value:"'freerdp' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-cache1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-codec1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-common1.1.0", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-core1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-crypto1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-gdi1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-locale1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-primitives1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-rail1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-utils1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-asn1-0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-bcrypt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credentials0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credui0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crypto0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dsparse0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-environment0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-error0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-file0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-handle0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-heap0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-input0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-interlocked0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-io0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-library0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-path0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pipe0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pool0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-registry0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-rpc0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspi0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspicli0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-synch0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sysinfo0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-thread0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-timezone0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-utils0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winhttp0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winsock0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1", rls:"DEB8"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freerdp-x11-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-cache1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-codec1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-common1.1.0", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-core1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-crypto1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-gdi1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-locale1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-plugins-standard-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-primitives1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-rail1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-utils1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-asn1-0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-bcrypt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credentials0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-credui0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crt0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-crypto0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dev", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-dsparse0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-environment0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-error0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-file0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-handle0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-heap0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-input0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-interlocked0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-io0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-library0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-path0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pipe0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-pool0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-registry0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-rpc0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspi0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sspicli0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-synch0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-sysinfo0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-thread0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-timezone0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-utils0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winhttp0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwinpr-winsock0.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client-dbg", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1", rls:"DEB9"))) {
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
