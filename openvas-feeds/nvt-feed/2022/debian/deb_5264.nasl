# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705264");
  script_cve_id("CVE-2022-41704", "CVE-2022-42890");
  script_tag(name:"creation_date", value:"2022-10-31 02:00:17 +0000 (Mon, 31 Oct 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 18:19:40 +0000 (Fri, 28 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5264-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5264-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5264");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/batik");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'batik' package(s) announced via the DSA-5264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Apache Batik, a SVG library for Java, allowed attackers to run arbitrary Java code by processing a malicious SVG file.

For the stable distribution (bullseye), these problems have been fixed in version 1.12-4+deb11u1.

We recommend that you upgrade your batik packages.

For the detailed security status of batik please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'batik' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbatik-java", ver:"1.12-4+deb11u1", rls:"DEB11"))) {
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
