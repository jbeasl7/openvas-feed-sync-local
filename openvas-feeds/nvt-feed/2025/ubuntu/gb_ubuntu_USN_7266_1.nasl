# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7266.1");
  script_cve_id("CVE-2017-0691", "CVE-2020-19858", "CVE-2020-22628", "CVE-2020-35530", "CVE-2020-35531", "CVE-2020-35532", "CVE-2020-35533", "CVE-2021-32142", "CVE-2023-1729");
  script_tag(name:"creation_date", value:"2025-02-13 09:14:31 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-02-14T08:35:38+0000");
  script_tag(name:"last_modification", value:"2025-02-14 08:35:38 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 18:29:35 +0000 (Tue, 14 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-7266-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7266-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7266-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'digikam' package(s) announced via the USN-7266-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zinuo Han and Ao Wang discovered that the Android DNG SDK, vendored in
digiKam, did not correctly parse certain files. An attacker could possibly
use this issue to execute arbitrary code. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2017-0691)

It was discovered that Platinum Upnp SDK, vendored in digiKam, was
vulnerable to a path traversal attack. An attacker could possibly use this
issue to leak sensitive information. This issue only affected
Ubuntu 20.04 LTS. (CVE-2020-19858)

It was discovered that LibRaw, vendored in digiKam, did not correctly
handle certain memory operations. If a user or automated system were
tricked into opening a specially crafted file, an attacker could possibly
use this issue to leak sensitive information. This issue only affected
Ubuntu 20.04 LTS. (CVE-2020-22628)

It was discovered that LibRaw, vendored in digiKam, did not correctly
handle certain memory operations. If a user or automated system were
tricked into opening a specially crafted file, an attacker could possibly
use this issue to cause a denial of service or execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-35530,
CVE-2020-35531, CVE-2020-35532, CVE-2020-35533)

It was discovered that LibRaw, vendored in digiKam, did not correctly
handle certain memory operations. If a user or automated system were
tricked into opening a specially crafted file, an attacker could possibly
use this issue to cause a denial of service or execute arbitrary code.
This issue only affected Ubuntu 20.04 LTS. (CVE-2021-32142)

It was discovered that LibRaw, vendored in digiKam, did not correctly
handle certain memory operations. If a user or automated system were
tricked into opening a specially crafted file, an attacker could possibly
use this issue to cause a denial of service or execute arbitrary code.
This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2023-1729)");

  script_tag(name:"affected", value:"'digikam' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"digikam", ver:"4:4.12.0-0ubuntu7+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"showfoto", ver:"4:4.12.0-0ubuntu7+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"digikam", ver:"4:5.6.0-0ubuntu10+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"showfoto", ver:"4:5.6.0-0ubuntu10+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"digikam", ver:"4:6.4.0+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"showfoto", ver:"4:6.4.0+dfsg-3ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"digikam", ver:"4:7.5.0-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"showfoto", ver:"4:7.5.0-3ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
