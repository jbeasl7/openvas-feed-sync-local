# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843198");
  script_cve_id("CVE-2016-9604", "CVE-2017-0605", "CVE-2017-2671", "CVE-2017-7277", "CVE-2017-7472", "CVE-2017-7618", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-7895", "CVE-2017-7979", "CVE-2017-8063", "CVE-2017-8064", "CVE-2017-8067");
  script_tag(name:"creation_date", value:"2017-06-08 04:02:59 +0000 (Thu, 08 Jun 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-11 14:19:16 +0000 (Thu, 11 May 2017)");

  script_name("Ubuntu: Security Advisory (USN-3314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.04");

  script_xref(name:"Advisory-ID", value:"USN-3314-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3314-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-raspi2' package(s) announced via the USN-3314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the keyring implementation in the Linux kernel in
some situations did not prevent special internal keyrings from being joined
by userspace keyrings. A privileged local attacker could use this to bypass
module verification. (CVE-2016-9604)

It was discovered that a buffer overflow existed in the trace subsystem in
the Linux kernel. A privileged local attacker could use this to execute
arbitrary code. (CVE-2017-0605)

Daniel Jiang discovered that a race condition existed in the ipv4 ping
socket implementation in the Linux kernel. A local privileged attacker
could use this to cause a denial of service (system crash). (CVE-2017-2671)

JongHwan Kim discovered an out-of-bounds read in the TCP stack of the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or leak sensitive information. (CVE-2017-7277)

Eric Biggers discovered a memory leak in the keyring implementation in the
Linux kernel. A local attacker could use this to cause a denial of service
(memory consumption). (CVE-2017-7472)

Sabrina Dubroca discovered that the asynchronous cryptographic hash (ahash)
implementation in the Linux kernel did not properly handle a full request
queue. A local attacker could use this to cause a denial of service
(infinite recursion). (CVE-2017-7618)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly handle certain long
RPC replies. A remote attacker could use this to cause a denial of service
(system crash). (CVE-2017-7645)

Tommi Rantala and Brad Spengler discovered that the memory manager in the
Linux kernel did not properly enforce the CONFIG_STRICT_DEVMEM protection
mechanism. A local attacker with access to /dev/mem could use this to
expose sensitive information or possibly execute arbitrary code.
(CVE-2017-7889)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly check for the end of
buffer. A remote attacker could use this to craft requests that cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-7895)

Fabian Grunbichler discovered that the Packet action API implementation in
the Linux kernel improperly handled uninitialized data. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-7979)

It was discovered that the Conexant USB driver in the Linux kernel
improperly handled memory in some configurations. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-8063)

It was discovered that the DVD USB framework in the Linux kernel improperly
handled memory in some configurations. A local attacker could use this to
cause a denial of service (system crash). (CVE-2017-8064)

It was discovered that the virtio console driver in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-raspi2' package(s) on Ubuntu 17.04.");

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

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.10.0-1006-raspi2", ver:"4.10.0-1006.8", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.10.0-22-generic", ver:"4.10.0-22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.10.0-22-generic-lpae", ver:"4.10.0-22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.10.0-22-lowlatency", ver:"4.10.0-22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.10.0.22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.10.0.22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.10.0.22.24", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.10.0.1006.8", rls:"UBUNTU17.04"))) {
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
