# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845247");
  script_cve_id("CVE-2021-23177", "CVE-2021-31566", "CVE-2021-36976");
  script_tag(name:"creation_date", value:"2022-02-18 02:00:31 +0000 (Fri, 18 Feb 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 16:09:19 +0000 (Fri, 26 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5291-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5291-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-5291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled symlinks. If a
user or automated system were tricked into processing a specially crafted
archive, an attacker could possibly use this issue to change modes, times,
ACLs, and flags on arbitrary files. (CVE-2021-23177, CVE-2021-31566)

It was discovered that libarchive incorrectly handled certain RAR archives.
If a user or automated system were tricked into processing a specially
crafted RAR archive, an attacker could use this issue to cause libarchive
to crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2021-36976)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.4.0-2ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libarchive13", ver:"3.4.3-2ubuntu0.1", rls:"UBUNTU21.10"))) {
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
