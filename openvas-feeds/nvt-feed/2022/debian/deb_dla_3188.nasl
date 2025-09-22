# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893188");
  script_cve_id("CVE-2019-16167", "CVE-2019-19725", "CVE-2022-39377");
  script_tag(name:"creation_date", value:"2022-11-15 02:00:17 +0000 (Tue, 15 Nov 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-13 20:06:47 +0000 (Fri, 13 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-3188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3188-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3188-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sysstat");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sysstat' package(s) announced via the DLA-3188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There were a couple of security issues found in sysstat, system performance tools for Linux, which are as follows:

CVE-2019-16167

sysstat before 12.1.6 has memory corruption due to an Integer Overflow in remap_struct() in sa_common.c.

CVE-2019-19725

sysstat through 12.2.0 has a double free in check_file_actlst in sa_common.c.

CVE-2022-39377

On 32 bit systems, allocate_structures contains a size_t overflow in sa_common.c. The allocate_structures function insufficiently checks bounds before arithmetic multiplication, allowing for an overflow in the size allocated for the buffer representing system activities. This issue may lead to Remote Code Execution (RCE).

For Debian 10 buster, these problems have been fixed in version 12.0.3-2+deb10u1.

We recommend that you upgrade your sysstat packages.

For the detailed security status of sysstat please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sysstat' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"isag", ver:"12.0.3-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sysstat", ver:"12.0.3-2+deb10u1", rls:"DEB10"))) {
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
