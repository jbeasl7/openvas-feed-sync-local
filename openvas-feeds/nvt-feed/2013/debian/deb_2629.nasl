# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702629");
  script_cve_id("CVE-2009-5030", "CVE-2012-3358", "CVE-2012-3535");
  script_tag(name:"creation_date", value:"2013-02-24 23:00:00 +0000 (Sun, 24 Feb 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2629-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2629-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2629");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg' package(s) announced via the DSA-2629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2009-5030

Heap memory corruption leading to invalid free when processing certain Gray16 TIFF images.

CVE-2012-3358

Huzaifa Sidhpurwala of the Red Hat Security Response Team found a heap-based buffer overflow in JPEG2000 image parsing.

CVE-2012-3535

Huzaifa Sidhpurwala of the Red Hat Security Response Team found a heap-based buffer overflow when decoding JPEG2000 images.

For the stable distribution (squeeze), these problems have been fixed in version 1.3+dfsg-4+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, these problems have been fixed in version 1.3+dfsg-4.6.

We recommend that you upgrade your openjpeg packages.");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg-dev", ver:"1.3+dfsg-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2", ver:"1.3+dfsg-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenjpeg2-dbg", ver:"1.3+dfsg-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1.3+dfsg-4+squeeze1", rls:"DEB6"))) {
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
