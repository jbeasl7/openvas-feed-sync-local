# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6713.1");
  script_cve_id("CVE-2024-24246");
  script_tag(name:"creation_date", value:"2024-03-26 04:08:43 +0000 (Tue, 26 Mar 2024)");
  script_version("2024-04-02T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-04-02 05:05:32 +0000 (Tue, 02 Apr 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-01 15:32:10 +0000 (Mon, 01 Apr 2024)");

  script_name("Ubuntu: Security Advisory (USN-6713-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU23\.10");

  script_xref(name:"Advisory-ID", value:"USN-6713-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6713-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qpdf' package(s) announced via the USN-6713-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QPDF incorrectly handled certain memory operations
when decoding JSON files. If a user or automated system were tricked into
processing a specially crafted JSON file, QPDF could be made to crash,
resulting in a denial of service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'qpdf' package(s) on Ubuntu 23.10.");

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

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libqpdf29", ver:"11.5.0-1ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qpdf", ver:"11.5.0-1ubuntu1.1", rls:"UBUNTU23.10"))) {
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
