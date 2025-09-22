# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892936");
  script_cve_id("CVE-2018-10887", "CVE-2018-10888", "CVE-2018-15501", "CVE-2018-8098", "CVE-2018-8099", "CVE-2020-12278", "CVE-2020-12279");
  script_tag(name:"creation_date", value:"2022-03-21 02:00:15 +0000 (Mon, 21 Mar 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-04 16:31:54 +0000 (Mon, 04 May 2020)");

  script_name("Debian: Security Advisory (DLA-2936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2936-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2936-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libgit2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgit2' package(s) announced via the DLA-2936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in libgit2, a low-level Git library, and are as follows:

CVE-2018-8098

Integer overflow in the index.c:read_entry() function while decompressing a compressed prefix length in libgit2 before v0.26.2 allows an attacker to cause a denial of service (out-of-bounds read) via a crafted repository index file.

CVE-2018-8099

Incorrect returning of an error code in the index.c:read_entry() function leads to a double free in libgit2 before v0.26.2, which allows an attacker to cause a denial of service via a crafted repository index file.

CVE-2018-10887

It has been discovered that an unexpected sign extension in git_delta_apply function in delta-apply.c file may lead to an integer overflow which in turn leads to an out of bound read, allowing to read before the base object. An attacker may use this flaw to leak memory addresses or cause a Denial of Service.

CVE-2018-10888

A missing check in git_delta_apply function in delta-apply.c file, may lead to an out-of-bound read while reading a binary delta file. An attacker may use this flaw to cause a Denial of Service.

CVE-2018-15501

In ng_pkt in transports/smart_pkt.c in libgit2, a remote attacker can send a crafted smart-protocol ng packet that lacks a '0' byte to trigger an out-of-bounds read that leads to DoS.

CVE-2020-12278

path.c mishandles equivalent filenames that exist because of NTFS Alternate Data Streams. This may allow remote code execution when cloning a repository. This issue is similar to CVE-2019-1352.

CVE-2020-12279

checkout.c mishandles equivalent filenames that exist because of NTFS short names. This may allow remote code execution when cloning a repository. This issue is similar to CVE-2019-1353.

For Debian 9 stretch, these problems have been fixed in version 0.25.1+really0.24.6-1+deb9u1.

We recommend that you upgrade your libgit2 packages.

For the detailed security status of libgit2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libgit2' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgit2-24", ver:"0.25.1+really0.24.6-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgit2-dev", ver:"0.25.1+really0.24.6-1+deb9u1", rls:"DEB9"))) {
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
