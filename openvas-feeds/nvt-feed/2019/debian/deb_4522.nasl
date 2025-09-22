# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704522");
  script_cve_id("CVE-2018-19502", "CVE-2018-19503", "CVE-2018-19504", "CVE-2018-20194", "CVE-2018-20195", "CVE-2018-20196", "CVE-2018-20197", "CVE-2018-20198", "CVE-2018-20357", "CVE-2018-20358", "CVE-2018-20359", "CVE-2018-20361", "CVE-2018-20362", "CVE-2019-15296");
  script_tag(name:"creation_date", value:"2019-09-16 02:00:15 +0000 (Mon, 16 Sep 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-29 16:43:49 +0000 (Thu, 29 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4522-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4522-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4522-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4522");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/faad2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'faad2' package(s) announced via the DSA-4522-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in faad2, the Freeware Advanced Audio Coder. These vulnerabilities might allow remote attackers to cause denial-of-service, or potentially execute arbitrary code if crafted MPEG AAC files are processed.

For the oldstable distribution (stretch), these problems have been fixed in version 2.8.0~cvs20161113-1+deb9u2.

We recommend that you upgrade your faad2 packages.

For the detailed security status of faad2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'faad2' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"faad", ver:"2.8.0~cvs20161113-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"faad2-dbg", ver:"2.8.0~cvs20161113-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfaad-dev", ver:"2.8.0~cvs20161113-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfaad2", ver:"2.8.0~cvs20161113-1+deb9u2", rls:"DEB9"))) {
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
