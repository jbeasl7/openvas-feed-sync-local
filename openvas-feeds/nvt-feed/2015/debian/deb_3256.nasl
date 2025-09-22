# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703256");
  script_cve_id("CVE-2015-3622");
  script_tag(name:"creation_date", value:"2015-05-09 22:00:00 +0000 (Sat, 09 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3256-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3256-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3256");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libtasn1-6' package(s) announced via the DSA-3256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered a heap-based buffer overflow flaw in the way Libtasn1, a library to manage ASN.1 structures, decoded certain DER-encoded input. A specially crafted DER-encoded input could cause an application using the Libtasn1 library to crash, or potentially to execute arbitrary code.

For the stable distribution (jessie), this problem has been fixed in version 4.2-3+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 4.4-3.

For the unstable distribution (sid), this problem has been fixed in version 4.4-3.

We recommend that you upgrade your libtasn1-6 packages.");

  script_tag(name:"affected", value:"'libtasn1-6' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-3-bin", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-6", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-6-dbg", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-6-dev", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-bin", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtasn1-doc", ver:"4.2-3+deb8u1", rls:"DEB8"))) {
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
