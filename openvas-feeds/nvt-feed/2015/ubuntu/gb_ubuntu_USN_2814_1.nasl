# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842537");
  script_cve_id("CVE-2015-7869");
  script_tag(name:"creation_date", value:"2015-11-19 05:37:45 +0000 (Thu, 19 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:C");

  script_name("Ubuntu: Security Advisory (USN-2814-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2814-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2814-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nvidia-graphics-drivers-304, nvidia-graphics-drivers-304-updates, nvidia-graphics-drivers-340, nvidia-graphics-drivers-340-updates, nvidia-graphics-drivers-352, nvidia-graphics-drivers-352-updates' package(s) announced via the USN-2814-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the NVIDIA graphics drivers incorrectly sanitized
user mode inputs. A local attacker could use this issue to possibly gain
root privileges.");

  script_tag(name:"affected", value:"'nvidia-graphics-drivers-304, nvidia-graphics-drivers-304-updates, nvidia-graphics-drivers-340, nvidia-graphics-drivers-340-updates, nvidia-graphics-drivers-352, nvidia-graphics-drivers-352-updates' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304", ver:"304.131-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304-updates", ver:"304.131-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331-updates", ver:"340.96-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340", ver:"340.96-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340-updates", ver:"340.96-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304", ver:"304.131-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304-updates", ver:"304.131-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331", ver:"340.96-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331-updates", ver:"340.96-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340", ver:"340.96-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340-updates", ver:"340.96-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346", ver:"352.63-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346-updates", ver:"352.63-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352", ver:"352.63-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352-updates", ver:"352.63-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304", ver:"304.131-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304-updates", ver:"304.131-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331", ver:"340.96-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331-updates", ver:"340.96-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340", ver:"340.96-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340-updates", ver:"340.96-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346", ver:"352.63-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346-updates", ver:"352.63-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352", ver:"352.63-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352-updates", ver:"352.63-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304", ver:"304.131-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-304-updates", ver:"304.131-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331", ver:"340.96-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-331-updates", ver:"340.96-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340", ver:"340.96-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-340-updates", ver:"340.96-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346", ver:"352.63-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-346-updates", ver:"352.63-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352", ver:"352.63-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nvidia-352-updates", ver:"352.63-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
