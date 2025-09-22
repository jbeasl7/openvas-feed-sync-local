# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890890");
  script_cve_id("CVE-2017-7578");
  script_tag(name:"creation_date", value:"2018-01-16 23:00:00 +0000 (Tue, 16 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-12 14:45:28 +0000 (Wed, 12 Apr 2017)");

  script_name("Debian: Security Advisory (DLA-890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-890-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-890-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ming' package(s) announced via the DLA-890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were multiple heap-based buffer overflows in ming, a library to generate SWF (Flash) files.

The updated packages prevent a crash in the listswf utility due to a heap-based buffer overflow in the parseSWF_RGBA function and several other functions in parser.c.

AddressSanitizer flagged them as invalid writes of size 1 but the heap could be written to multiple times. The overflows are caused by a pointer behind the bounds of a statically allocated array of structs of type SWF_GRADIENTRECORD.

For Debian 7 Wheezy, this issue has been fixed in ming version 1:0.4.4-1.1+deb7u2.

We recommend that you upgrade your ming packages.");

  script_tag(name:"affected", value:"'ming' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libming-dev", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming-util", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming1", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswf-perl", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-dejavu", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-opensymbol", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-ming", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ming", ver:"1:0.4.4-1.1+deb7u2", rls:"DEB7"))) {
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
