# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845196");
  script_cve_id("CVE-2021-23437", "CVE-2021-34552", "CVE-2022-22815", "CVE-2022-22816", "CVE-2022-22817");
  script_tag(name:"creation_date", value:"2022-01-14 02:00:55 +0000 (Fri, 14 Jan 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-19 14:10:22 +0000 (Wed, 19 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-5227-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.04|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5227-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5227-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow' package(s) announced via the USN-5227-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to hang, resulting in a denial
of service. (CVE-2021-23437)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 21.04. (CVE-2021-34552)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2022-22815)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service. (CVE-2022-22816)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2022-22817)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"5.1.0-1ubuntu0.7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"5.1.0-1ubuntu0.7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"7.0.0-4ubuntu0.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.04") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"8.1.2-1ubuntu0.2", rls:"UBUNTU21.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"8.1.2+dfsg-0.3ubuntu0.1", rls:"UBUNTU21.10"))) {
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
