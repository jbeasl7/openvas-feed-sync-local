# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844007");
  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-20815", "CVE-2019-11091", "CVE-2019-5008", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2019-05-15 02:02:55 +0000 (Wed, 15 May 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 15:41:33 +0000 (Mon, 03 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-3978-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|18\.10|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3978-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3978-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/MDS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3978-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi Maisuradze, Dan
Horea Lutas, Andrei Lutas, Volodymyr Pikhur, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos,
Cristiano Giuffrida, Moritz Lipp, Michael Schwarz, and Daniel Gruss
discovered that memory previously stored in microarchitectural fill buffers
of an Intel CPU core may be exposed to a malicious process that is
executing on the same CPU core. A local attacker could use this to expose
sensitive information. (CVE-2018-12130)

Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Stephan
van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh
Razavi, Herbert Bos, and Cristiano Giuffrida discovered that memory
previously stored in microarchitectural load ports of an Intel CPU core may
be exposed to a malicious process that is executing on the same CPU core. A
local attacker could use this to expose sensitive information.
(CVE-2018-12127)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin, Daniel
Moghimi, Moritz Lipp, Michael Schwarz, Jo Van Bulck, Daniel Genkin, Daniel
Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom discovered that memory
previously stored in microarchitectural store buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same CPU
core. A local attacker could use this to expose sensitive information.
(CVE-2018-12126)

Kurtis Miller discovered that a buffer overflow existed in QEMU when
loading a device tree blob. A local attacker could use this to execute
arbitrary code. (CVE-2018-20815)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian Osterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos, and
Cristiano Giuffrida discovered that uncacheable memory previously stored in
microarchitectural buffers of an Intel CPU core may be exposed to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11091)

It was discovered that a NULL pointer dereference existed in the sun4u
power device implementation in QEMU. A local attacker could use this
to cause a denial of service. This issue only affected Ubuntu 18.10
and Ubuntu 19.04. (CVE-2019-5008)

William Bowling discovered that an information leak existed in the SLiRP
networking implementation of QEMU. An attacker could use this to expose
sensitive information. (CVE-2019-9824)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"2.0.0+dfsg-2ubuntu1.46", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.46", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.5+dfsg-5ubuntu10.38", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.5+dfsg-5ubuntu10.38", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.11+dfsg-1ubuntu7.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.11+dfsg-1ubuntu7.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.12+dfsg-3ubuntu8.7", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.12+dfsg-3ubuntu8.7", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:3.1+dfsg-2ubuntu3.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:3.1+dfsg-2ubuntu3.1", rls:"UBUNTU19.04"))) {
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
