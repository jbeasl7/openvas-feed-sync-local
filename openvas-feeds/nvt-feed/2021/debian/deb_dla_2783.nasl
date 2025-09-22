# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892783");
  script_cve_id("CVE-2021-32765");
  script_tag(name:"creation_date", value:"2021-10-13 01:00:09 +0000 (Wed, 13 Oct 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-07 15:43:09 +0000 (Thu, 07 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-2783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2783-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2783-1");
  script_xref(name:"URL", value:"https://github.com/redis/hiredis#reader-max-array-elements");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hiredis' package(s) announced via the DLA-2783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an integer-overflow vulnerability in hiredis, a C client library for communicating with Redis databases. This occurred within the handling and parsing of 'multi-bulk' replies.

CVE-2021-32765

Hiredis is a minimalistic C client library for the Redis database. In affected versions Hiredis is vulnurable to integer overflow if provided maliciously crafted or corrupted `RESP` `mult-bulk` protocol data. When parsing `multi-bulk` (array-like) replies, hiredis fails to check if `count * sizeof(redisReply*)` can be represented in `SIZE_MAX`. If it can not, and the `calloc()` call doesn't itself make this check, it would result in a short allocation and subsequent buffer overflow. Users of hiredis who are unable to update may set the [maxelements]([link moved to references]) context option to a value small enough that no overflow is possible.

For Debian 9 Stretch, these problems have been fixed in version 0.13.3-1+deb9u1.

We recommend that you upgrade your hiredis packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'hiredis' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libhiredis-dbg", ver:"0.13.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhiredis-dev", ver:"0.13.3-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhiredis0.13", ver:"0.13.3-1+deb9u1", rls:"DEB9"))) {
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
