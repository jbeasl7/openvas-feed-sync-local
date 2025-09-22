# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704818");
  script_cve_id("CVE-2020-10936", "CVE-2020-26932", "CVE-2020-29668", "CVE-2020-9369");
  script_tag(name:"creation_date", value:"2020-12-25 04:00:11 +0000 (Fri, 25 Dec 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-28 13:43:18 +0000 (Thu, 28 May 2020)");

  script_name("Debian: Security Advisory (DSA-4818-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4818-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/DSA-4818-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4818");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sympa");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sympa' package(s) announced via the DSA-4818-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Sympa, a mailing list manager, which could result in local privilege escalation, denial of service or unauthorized access via the SOAP API.

Additionally to mitigate CVE-2020-26880 the sympa_newaliases-wrapper is no longer installed setuid root by default. A new Debconf question is introduced to allow setuid installations in setups where it is needed.

For the stable distribution (buster), these problems have been fixed in version 6.2.40~dfsg-1+deb10u1.

We recommend that you upgrade your sympa packages.

For the detailed security status of sympa please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sympa' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sympa", ver:"6.2.40~dfsg-1+deb10u1", rls:"DEB10"))) {
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
