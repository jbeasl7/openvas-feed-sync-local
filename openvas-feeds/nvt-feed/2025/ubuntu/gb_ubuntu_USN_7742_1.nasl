# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7742.1");
  script_cve_id("CVE-2025-32988", "CVE-2025-32990", "CVE-2025-6395");
  script_tag(name:"creation_date", value:"2025-09-16 04:04:41 +0000 (Tue, 16 Sep 2025)");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 19:32:53 +0000 (Fri, 15 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7742-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7742-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7742-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-7742-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GnuTLS incorrectly handled exporting Subject
Alternative Name (SAN) entries containing an otherName. A remote attacker
could use this issue to cause GnuTLS to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2025-32988)

It was discovered that the GnuTLS certtool utility incorrectly handled
parsing certain template files. An attacker could use this issue to cause
GnuTLS to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2025-32990)

Stefan Buhler discovered that GnuTLS incorrectly handled parsing certain
template files. An attacker could possibly use this issue to cause GnuTLS
to crash, resulting in a denial of service. This issue only affected
Ubuntu 20.04 LTS. (CVE-2025-6395)");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.4.10-4ubuntu1.9+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.5.18-1ubuntu1.6+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.6.13-2ubuntu1.12+esm1", rls:"UBUNTU20.04 LTS"))) {
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
