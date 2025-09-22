# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703226");
  script_cve_id("CVE-2012-6696", "CVE-2012-6697", "CVE-2015-6674");
  script_tag(name:"creation_date", value:"2015-04-14 22:00:00 +0000 (Tue, 14 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-21 00:52:51 +0000 (Fri, 21 Apr 2017)");

  script_name("Debian: Security Advisory (DSA-3226-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3226-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3226-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3226");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'inspircd' package(s) announced via the DSA-3226-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adam discovered several problems in inspircd, an IRC daemon:

An incomplete patch for CVE-2012-1836 failed to adequately resolve the problem where maliciously crafted DNS requests could lead to remote code execution through a heap-based buffer overflow.

The incorrect processing of specific DNS packets could trigger an infinite loop, thus resulting in a denial of service.

For the stable distribution (wheezy), this problem has been fixed in version 2.0.5-1+deb7u1.

For the upcoming stable distribution (jessie) and unstable distribution (sid), this problem has been fixed in version 2.0.16-1.

We recommend that you upgrade your inspircd packages.");

  script_tag(name:"affected", value:"'inspircd' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"2.0.5-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.5-1+deb7u1", rls:"DEB7"))) {
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
