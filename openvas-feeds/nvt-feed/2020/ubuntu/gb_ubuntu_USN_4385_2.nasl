# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844468");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"creation_date", value:"2020-06-11 03:00:48 +0000 (Thu, 11 Jun 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 16:52:27 +0000 (Tue, 25 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-4385-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|19\.10|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4385-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4385-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1882890");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1883002");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-4385-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4385-1 provided updated Intel Processor Microcode. Unfortunately,
that update prevented certain processors in the Intel Skylake family
(06_4EH) from booting successfully. Additionally, on Ubuntu 20.04
LTS, late loading of microcode was enabled, which could lead to
system instability. This update reverts the microcode update for
the Skylake processor family and disables the late loading option on
Ubuntu 20.04 LTS.

Please note that the 'dis_ucode_ldr' kernel command line option can be
added in the boot menu to disable microcode loading for system recovery.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that memory contents previously stored in
 microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY
 read operations on Intel client and Xeon E3 processors may be briefly
 exposed to processes on the same or different processor cores. A local
 attacker could use this to expose sensitive information. (CVE-2020-0543)

 It was discovered that on some Intel processors, partial data values
 previously read from a vector register on a physical core may be propagated
 into unused portions of the store buffer. A local attacker could possible
 use this to expose sensitive information. (CVE-2020-0548)

 It was discovered that on some Intel processors, data from the most
 recently evicted modified L1 data cache (L1D) line may be propagated into
 an unused (invalid) L1D fill buffer. A local attacker could possibly use
 this to expose sensitive information. (CVE-2020-0549)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.0ubuntu0.19.10.2", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
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
