# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891573");
  script_cve_id("CVE-2016-0801", "CVE-2017-0561", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-9417");
  script_tag(name:"creation_date", value:"2018-11-12 23:00:00 +0000 (Mon, 12 Nov 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-12 14:22:11 +0000 (Mon, 12 Jun 2017)");

  script_name("Debian: Security Advisory (DLA-1573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1573-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1573-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firmware-nonfree' package(s) announced via the DLA-1573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the firmware for Broadcom BCM43xx wifi chips that may lead to a privilege escalation or loss of confidentiality.

CVE-2016-0801

Broadgate Team discovered flaws in packet processing in the Broadcom wifi firmware and proprietary drivers that could lead to remote code execution. However, this vulnerability is not believed to affect the drivers used in Debian.

CVE-2017-0561

Gal Beniamini of Project Zero discovered a flaw in the TDLS implementation in Broadcom wifi firmware. This could be exploited by an attacker on the same WPA2 network to execute code on the wifi microcontroller.

CVE-2017-9417 / #869639 Nitay Artenstein of Exodus Intelligence discovered a flaw in the WMM implementation in Broadcom wifi firmware. This could be exploited by a nearby attacker to execute code on the wifi microcontroller.

CVE-2017-13077 / CVE-2017-13078 / CVE-2017-13079 / CVE-2017-13080 / CVE-2017-13081 Mathy Vanhoef of the imec-DistriNet research group of KU Leuven discovered multiple vulnerabilities in the WPA protocol used for authentication in wireless networks, dubbed KRACK. An attacker exploiting the vulnerabilities could force the vulnerable system to reuse cryptographic session keys, enabling a range of cryptographic attacks against the ciphers used in WPA1 and WPA2. These vulnerabilities are only being fixed for certain Broadcom wifi chips, and might still be present in firmware for other wifi hardware.

For Debian 8 Jessie, these problems have been fixed in version 20161130-4~deb8u1. This version also adds new firmware and packages for use with Linux 4.9, and re-adds firmware-{adi,ralink} as transitional packages.

We recommend that you upgrade your firmware-nonfree packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'firmware-nonfree' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"firmware-adi", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-amd-graphics", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-atheros", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-bnx2x", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-brcm80211", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-cavium", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intel-sound", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-intelwimax", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ipw2x00", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ivtv", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-iwlwifi", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-libertas", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux-nonfree", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-misc-nonfree", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-myricom", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-netxen", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-qlogic", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ralink", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-realtek", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-samsung", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-siano", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firmware-ti-connectivity", ver:"20161130-4~deb8u1", rls:"DEB8"))) {
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
