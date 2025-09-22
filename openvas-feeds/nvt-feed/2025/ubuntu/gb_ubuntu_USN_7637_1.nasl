# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7637.1");
  script_cve_id("CVE-2023-0645", "CVE-2023-35790", "CVE-2024-11403", "CVE-2024-11498");
  script_tag(name:"creation_date", value:"2025-07-17 04:15:48 +0000 (Thu, 17 Jul 2025)");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-23 19:48:17 +0000 (Wed, 23 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7637-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7637-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jpeg-xl' package(s) announced via the USN-7637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libjxl did not perform proper bounds checking
when parsing Exif tags. An attacker could possibly use this issue to
cause libjxl to crash, resulting in a denial of service. (CVE-2023-0645)

It was discovered that libjxl did not perform proper bounds checking
when decoding patches. An attacker could possibly use this issue to
cause libjxl to enter an infinite loop, resulting in a denial of
service. (CVE-2023-35790)

It was discovered that libjxl did not perform proper bounds checking
when performing JPEG recompression. An attacker could possibly use this
issue to cause libjxl to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2024-11403)

It was discovered that libjxl incorrectly handled parsing certain image
files. An attacker could possibly use this issue to cause libjxl to
consume excessive amounts of memory, resulting in a denial of service.
(CVE-2024-11498)");

  script_tag(name:"affected", value:"'jpeg-xl' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjpegxl-java", ver:"0.7.0-10.2ubuntu6.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjxl-tools", ver:"0.7.0-10.2ubuntu6.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjxl0.7", ver:"0.7.0-10.2ubuntu6.1", rls:"UBUNTU24.04 LTS"))) {
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
