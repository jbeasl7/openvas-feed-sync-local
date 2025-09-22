# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843071");
  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-10162", "CVE-2016-7479", "CVE-2016-9137", "CVE-2016-9935", "CVE-2016-9936", "CVE-2017-5340");
  script_tag(name:"creation_date", value:"2017-03-03 04:50:08 +0000 (Fri, 03 Mar 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 18:04:46 +0000 (Wed, 11 Jan 2017)");

  script_name("Ubuntu: Security Advisory (USN-3211-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|16\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3211-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3211-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1668017");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0' package(s) announced via the USN-3211-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3211-1 fixed vulnerabilities in PHP by updating to the new 7.0.15
upstream release. PHP 7.0.15 introduced a regression when using MySQL with
large blobs. This update fixes the problem with a backported fix.

Original advisory details:

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-7479)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-9137)

 It was discovered that PHP incorrectly handled unserializing certain
 wddxPacket XML documents. A remote attacker could use this issue to cause
 PHP to crash, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2016-9935)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2016-9936)

 It was discovered that PHP incorrectly handled certain EXIF data. A remote
 attacker could use this issue to cause PHP to crash, resulting in a denial
 of service. (CVE-2016-10158)

 It was discovered that PHP incorrectly handled certain PHAR archives. A
 remote attacker could use this issue to cause PHP to crash or consume
 resources, resulting in a denial of service. (CVE-2016-10159)

 It was discovered that PHP incorrectly handled certain PHAR archives. A
 remote attacker could use this issue to cause PHP to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2016-10160)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service. (CVE-2016-10161)

 It was discovered that PHP incorrectly handled unserializing certain
 wddxPacket XML documents. A remote attacker could use this issue to cause
 PHP to crash, resulting in a denial of service. (CVE-2016-10162)

 It was discovered that PHP incorrectly handled certain invalid objects when
 unserializing data. A remote attacker could use this issue to cause PHP to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2017-5340)");

  script_tag(name:"affected", value:"'php7.0' package(s) on Ubuntu 16.04, Ubuntu 16.10.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.15-0ubuntu0.16.04.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.15-0ubuntu0.16.04.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.15-0ubuntu0.16.04.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.15-0ubuntu0.16.04.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.15-0ubuntu0.16.10.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.15-0ubuntu0.16.10.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.15-0ubuntu0.16.10.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.15-0ubuntu0.16.10.4", rls:"UBUNTU16.10"))) {
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
