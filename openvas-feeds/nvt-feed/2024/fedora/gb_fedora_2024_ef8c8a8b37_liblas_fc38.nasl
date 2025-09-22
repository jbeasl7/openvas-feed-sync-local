# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886249");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2024-27507");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:02 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for liblas (FEDORA-2024-ef8c8a8b37)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ef8c8a8b37");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3QRV2D4GYUZNZRJHVGFSYSOSZLCETI4E");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblas'
  package(s) announced via the FEDORA-2024-ef8c8a8b37 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libLAS is a C/C++ library for reading and writing the very common LAS LiDAR
format. The ASPRS LAS format is a sequential binary format used to store
data from LiDAR sensors and by LiDAR processing software for data
interchange and archival.");

  script_tag(name:"affected", value:"'liblas' package(s) on Fedora 38.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"liblas", rpm:"liblas~1.8.2~0.12.gitf1da555.fc38", rls:"FC38"))) {
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