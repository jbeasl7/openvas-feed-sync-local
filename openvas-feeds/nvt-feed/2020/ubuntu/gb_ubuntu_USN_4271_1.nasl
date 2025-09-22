# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844334");
  script_cve_id("CVE-2019-5068");
  script_tag(name:"creation_date", value:"2020-02-07 04:00:23 +0000 (Fri, 07 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 20:32:51 +0000 (Tue, 12 Nov 2019)");

  script_name("Ubuntu: Security Advisory (USN-4271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4271-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4271-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa' package(s) announced via the USN-4271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Brown discovered that Mesa incorrectly handled shared memory
permissions. A local attacker could use this issue to obtain and possibly
alter sensitive information belonging to another user.");

  script_tag(name:"affected", value:"'mesa' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libd3dadapter9-mesa", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegl-mesa0", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegl1-mesa", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgbm1", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-mesa-dri", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-mesa-glx", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglapi-mesa", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgles2-mesa", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglx-mesa0", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libosmesa6", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwayland-egl1-mesa", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxatracker2", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-opencl-icd", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-va-drivers", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-vdpau-drivers", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-vulkan-drivers", ver:"19.2.8-0ubuntu0~18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libd3dadapter9-mesa", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegl-mesa0", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libegl1-mesa", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgbm1", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-mesa-dri", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgl1-mesa-glx", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglapi-mesa", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgles2-mesa", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglx-mesa0", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libosmesa6", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwayland-egl1-mesa", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxatracker2", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-opencl-icd", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-va-drivers", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-vdpau-drivers", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mesa-vulkan-drivers", ver:"19.2.8-0ubuntu0~19.10.2", rls:"UBUNTU19.10"))) {
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
