# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845157");
  script_cve_id("CVE-2021-28831", "CVE-2021-42374", "CVE-2021-42378", "CVE-2021-42379", "CVE-2021-42380", "CVE-2021-42381", "CVE-2021-42382", "CVE-2021-42384", "CVE-2021-42385", "CVE-2021-42386");
  script_tag(name:"creation_date", value:"2021-12-08 02:00:29 +0000 (Wed, 08 Dec 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 21:50:55 +0000 (Tue, 16 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-5179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.04|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5179-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5179-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the USN-5179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BusyBox incorrectly handled certain malformed gzip
archives. If a user or automated system were tricked into processing a
specially crafted gzip archive, a remote attacker could use this issue to
cause BusyBox to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2021-28831)

It was discovered that BusyBox incorrectly handled certain malformed LZMA
archives. If a user or automated system were tricked into processing a
specially crafted LZMA archive, a remote attacker could use this issue to
cause BusyBox to crash, resulting in a denial of service, or possibly
leak sensitive information. (CVE-2021-42374)

Vera Mens, Uri Katz, Tal Keren, Sharon Brizinov, and Shachar Menashe
discovered that BusyBox incorrectly handled certain awk patterns. If a user
or automated system were tricked into processing a specially crafted awk
pattern, a remote attacker could use this issue to cause BusyBox to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2021-42378, CVE-2021-42379, CVE-2021-42380, CVE-2021-42381,
CVE-2021-42382, CVE-2021-42384, CVE-2021-42385, CVE-2021-42386)");

  script_tag(name:"affected", value:"'busybox' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.27.2-2ubuntu3.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.27.2-2ubuntu3.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.27.2-2ubuntu3.4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.30.1-4ubuntu6.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.30.1-4ubuntu6.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.30.1-4ubuntu6.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.30.1-6ubuntu2.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.30.1-6ubuntu2.1", rls:"UBUNTU21.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.30.1-6ubuntu2.1", rls:"UBUNTU21.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"busybox", ver:"1:1.30.1-6ubuntu3.1", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-initramfs", ver:"1:1.30.1-6ubuntu3.1", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"busybox-static", ver:"1:1.30.1-6ubuntu3.1", rls:"UBUNTU21.10"))) {
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
