# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705025");
  script_cve_id("CVE-2021-4076");
  script_tag(name:"creation_date", value:"2021-12-20 09:56:42 +0000 (Mon, 20 Dec 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-09 19:45:09 +0000 (Wed, 09 Mar 2022)");

  script_name("Debian: Security Advisory (DSA-5025-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5025-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5025-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5025");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tang");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tang' package(s) announced via the DSA-5025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in tang, a network-based cryptographic binding server, which could result in leak of private keys.

For the stable distribution (bullseye), this problem has been fixed in version 8-3+deb11u1.

We recommend that you upgrade your tang packages.

For the detailed security status of tang please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'tang' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"tang", ver:"8-3+deb11u1", rls:"DEB11"))) {
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
