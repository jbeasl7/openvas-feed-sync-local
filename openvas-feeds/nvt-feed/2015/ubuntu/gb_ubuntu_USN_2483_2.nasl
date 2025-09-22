# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842075");
  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158");
  script_tag(name:"creation_date", value:"2015-01-27 04:50:46 +0000 (Tue, 27 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2483-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2483-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2483-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-2483-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2483-1 fixed vulnerabilities in JasPer. This update provides the
corresponding fix for the JasPer library embedded in the Ghostscript
package.

Original advisory details:

 Jose Duart discovered that JasPer incorrectly handled ICC color profiles in
 JPEG-2000 image files. If a user were tricked into opening a specially
 crafted JPEG-2000 image file, a remote attacker could cause JasPer to crash
 or possibly execute arbitrary code with user privileges. (CVE-2014-8137)

 Jose Duart discovered that JasPer incorrectly decoded certain malformed
 JPEG-2000 image files. If a user were tricked into opening a specially
 crafted JPEG-2000 image file, a remote attacker could cause JasPer to crash
 or possibly execute arbitrary code with user privileges. (CVE-2014-8138)

 It was discovered that JasPer incorrectly handled certain malformed
 JPEG-2000 image files. If a user were tricked into opening a specially
 crafted JPEG-2000 image file, a remote attacker could cause JasPer to crash
 or possibly execute arbitrary code with user privileges. (CVE-2014-8157)

 It was discovered that JasPer incorrectly handled memory when processing
 JPEG-2000 image files. If a user were tricked into opening a specially
 crafted JPEG-2000 image file, a remote attacker could cause JasPer to crash
 or possibly execute arbitrary code with user privileges. (CVE-2014-8158)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.71.dfsg.1-0ubuntu5.7", rls:"UBUNTU10.04 LTS"))) {
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
