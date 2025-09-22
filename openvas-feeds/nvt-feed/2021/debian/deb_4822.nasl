# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704822");
  script_cve_id("CVE-2020-29361", "CVE-2020-29362", "CVE-2020-29363");
  script_tag(name:"creation_date", value:"2021-01-02 04:00:11 +0000 (Sat, 02 Jan 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 19:50:40 +0000 (Thu, 07 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-4822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4822-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4822-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4822");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/p11-kit");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'p11-kit' package(s) announced via the DSA-4822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Cook reported several memory safety issues affecting the RPC protocol in p11-kit, a library providing a way to load and enumerate PKCS#11 modules.

For the stable distribution (buster), these problems have been fixed in version 0.23.15-2+deb10u1.

We recommend that you upgrade your p11-kit packages.

For the detailed security status of p11-kit please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'p11-kit' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libp11-kit-dev", ver:"0.23.15-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libp11-kit0", ver:"0.23.15-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"p11-kit", ver:"0.23.15-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"p11-kit-modules", ver:"0.23.15-2+deb10u1", rls:"DEB10"))) {
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
