# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703774");
  script_cve_id("CVE-2016-10165");
  script_tag(name:"creation_date", value:"2017-01-28 23:00:00 +0000 (Sat, 28 Jan 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 15:05:10 +0000 (Thu, 09 Feb 2017)");

  script_name("Debian: Security Advisory (DSA-3774-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3774-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3774-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3774");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lcms2' package(s) announced via the DSA-3774-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ibrahim M. El-Sayed discovered an out-of-bounds heap read vulnerability in the function Type_MLU_Read in lcms2, the Little CMS 2 color management library, which can be triggered by an image with a specially crafted ICC profile and leading to a heap memory leak or denial-of-service for applications using the lcms2 library.

For the stable distribution (jessie), this problem has been fixed in version 2.6-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem has been fixed in version 2.8-4.

We recommend that you upgrade your lcms2 packages.");

  script_tag(name:"affected", value:"'lcms2' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-2", ver:"2.6-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-dbg", ver:"2.6-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-dev", ver:"2.6-3+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblcms2-utils", ver:"2.6-3+deb8u1", rls:"DEB8"))) {
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
