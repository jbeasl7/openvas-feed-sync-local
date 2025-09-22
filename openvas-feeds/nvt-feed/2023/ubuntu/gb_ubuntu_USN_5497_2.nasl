# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5497.2");
  script_cve_id("CVE-2018-11212", "CVE-2018-11213", "CVE-2018-11214", "CVE-2018-11813", "CVE-2020-14152");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 19:10:53 +0000 (Thu, 18 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-5497-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5497-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5497-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg6b' package(s) announced via the USN-5497-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5497-1 fixed vulnerabilities in Libjpeg6b. This update provides
the corresponding updates for Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that Libjpeg6b was not properly performing bounds
 checks when compressing PPM and Targa image files. An attacker could
 possibly use this issue to cause a denial of service.
 (CVE-2018-11212)

 Chijin Zhou discovered that Libjpeg6b was incorrectly handling the
 EOF character in input data when generating JPEG files. An attacker
 could possibly use this issue to force the execution of a large loop,
 force excessive memory consumption, and cause a denial of service.
 (CVE-2018-11813)

 Sheng Shu and Dongdong She discovered that Libjpeg6b was not properly
 limiting the amount of memory being used when it was performing
 decompression or multi-pass compression operations. An attacker could
 possibly use this issue to force excessive memory consumption and
 cause a denial of service. (CVE-2020-14152)");

  script_tag(name:"affected", value:"'libjpeg6b' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg62", ver:"1:6b2-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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
