# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891126");
  script_cve_id("CVE-2017-13720", "CVE-2017-13722");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-03 17:28:19 +0000 (Fri, 03 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-1126-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1126-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-1126-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxfont' package(s) announced via the DLA-1126-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there two vulnerabilities the library providing font selection and rasterisation, libxfont:

CVE-2017-13720

If a pattern contained a '?' character any character in the string is skipped even if it was a '0'. The rest of the matching then read invalid memory.

CVE-2017-13722

A malformed PCF file could cause the library to make reads from random heap memory that was behind the `strings` buffer, leading to an application crash or a information leak.

For Debian 7 Wheezy, this issue has been fixed in libxfont version 1:1.4.5-5+deb7u1.

We recommend that you upgrade your libxfont packages.");

  script_tag(name:"affected", value:"'libxfont' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libxfont-dev", ver:"1:1.4.5-5+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1", ver:"1:1.4.5-5+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-dbg", ver:"1:1.4.5-5+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxfont1-udeb", ver:"1:1.4.5-5+deb7u1", rls:"DEB7"))) {
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
