# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844944");
  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_tag(name:"creation_date", value:"2021-05-19 03:00:56 +0000 (Wed, 19 May 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 15:31:57 +0000 (Tue, 24 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4628-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10|21\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4628-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4628-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-4628-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4628-1 provided updated Intel Processor Microcode for various processor
types. This update provides the corresponding updates for some additional
processor types.

Original advisory details:

 Moritz Lipp, Michael Schwarz, Andreas Kogler, David Oswald, Catherine
 Easdon, Claudio Canella, and Daniel Gruss discovered that the Intel Running
 Average Power Limit (RAPL) feature of some Intel processors allowed a side-
 channel attack based on power consumption measurements. A local attacker
 could possibly use this to expose sensitive information. (CVE-2020-8695)

 Ezra Caltum, Joseph Nuzman, Nir Shildan and Ofir Joseff discovered that
 some Intel(R) Processors did not properly remove sensitive information
 before storage or transfer in some situations. A local attacker could
 possibly use this to expose sensitive information. (CVE-2020-8696)

 Ezra Caltum, Joseph Nuzman, Nir Shildan and Ofir Joseff discovered that
 some Intel(R) Processors did not properly isolate shared resources in some
 situations. A local attacker could possibly use this to expose sensitive
 information. (CVE-2020-8698)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10, Ubuntu 21.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20210216.0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20210216.0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20210216.0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20210216.0ubuntu0.21.04.1", rls:"UBUNTU21.04"))) {
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
