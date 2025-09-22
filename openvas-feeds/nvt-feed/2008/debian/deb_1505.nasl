# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60439");
  script_cve_id("CVE-2007-4571");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1505-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1505-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1505");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'alsa-driver, alsa-modules-i386' package(s) announced via the DSA-1505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Takashi Iwai supplied a fix for a memory leak in the snd_page_alloc module. Local users could exploit this issue to obtain sensitive information from the kernel (CVE-2007-4571).

For the oldstable distribution (sarge), this problem has been fixed in version 1.0.8-7sarge1. The prebuilt modules provided by alsa-modules-i386 have been rebuilt to take advantage of this update, and are available in version 1.0.8+2sarge2.

For the stable distribution (etch), this problem has been fixed in version 1.0.13-5etch1. This issue was already fixed for the version of ALSA provided by linux-2.6 in DSA 1479.

For the unstable distributions (sid), this problem was fixed in version 1.0.15-1.

We recommend that you upgrade your alsa-driver and alsa-modules-i386 packages.");

  script_tag(name:"affected", value:"'alsa-driver, alsa-modules-i386' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"alsa-base", ver:"1.0.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-headers", ver:"1.0.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-386", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-586tsc", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-686-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k6", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-modules-2.4.27-4-k7-smp", ver:"1.0.8+2sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-source", ver:"1.0.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"alsa-base", ver:"1.0.13-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"alsa-source", ver:"1.0.13-5etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-sound-base", ver:"1.0.13-5etch1", rls:"DEB4"))) {
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
