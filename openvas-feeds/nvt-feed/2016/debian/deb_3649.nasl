# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703649");
  script_cve_id("CVE-2016-6313");
  script_tag(name:"creation_date", value:"2016-08-16 22:00:00 +0000 (Tue, 16 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-16 20:06:24 +0000 (Fri, 16 Dec 2016)");

  script_name("Debian: Security Advisory (DSA-3649-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3649-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3649-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3649");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnupg' package(s) announced via the DSA-3649-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Felix Doerre and Vladimir Klebanov from the Karlsruhe Institute of Technology discovered a flaw in the mixing functions of GnuPG's random number generator. An attacker who obtains 4640 bits from the RNG can trivially predict the next 160 bits of output.

A first analysis on the impact of this bug for GnuPG shows that existing RSA keys are not weakened. For DSA and Elgamal keys it is also unlikely that the private key can be predicted from other public information.

For the stable distribution (jessie), this problem has been fixed in version 1.4.18-7+deb8u2.

We recommend that you upgrade your gnupg packages.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg-udeb", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-udeb", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.18-7+deb8u2", rls:"DEB8"))) {
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
