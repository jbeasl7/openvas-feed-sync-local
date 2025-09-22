# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892981");
  script_cve_id("CVE-2018-5786", "CVE-2020-25467", "CVE-2021-27345", "CVE-2021-27347", "CVE-2022-26291");
  script_tag(name:"creation_date", value:"2022-04-14 01:00:09 +0000 (Thu, 14 Apr 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 15:07:09 +0000 (Tue, 05 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-2981-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2981-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2981-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lrzip");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lrzip' package(s) announced via the DLA-2981-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in lrzip, a compression program. Invalid pointers, use-after-free and infinite loops would allow attackers to cause a denial of service or possibly other unspecified impact via a crafted compressed file.

CVE-2018-5786

There is an infinite loop and application hang in the get_fileinfo function (lrzip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a crafted lrz file.

CVE-2020-25467

A null pointer dereference was discovered lzo_decompress_buf in stream.c which allows an attacker to cause a denial of service (DOS) via a crafted compressed file.

CVE-2021-27345

A null pointer dereference was discovered in ucompthread in stream.c which allows attackers to cause a denial of service (DOS) via a crafted compressed file.

CVE-2021-27347

Use after free in lzma_decompress_buf function in stream.c in allows attackers to cause Denial of Service (DoS) via a crafted compressed file.

CVE-2022-26291

lrzip was discovered to contain a multiple concurrency use-after-free between the functions zpaq_decompress_buf() and clear_rulist(). This vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted lrz file.

For Debian 9 stretch, these problems have been fixed in version 0.631-1+deb9u2.

We recommend that you upgrade your lrzip packages.

For the detailed security status of lrzip please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'lrzip' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lrzip", ver:"0.631-1+deb9u2", rls:"DEB9"))) {
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
