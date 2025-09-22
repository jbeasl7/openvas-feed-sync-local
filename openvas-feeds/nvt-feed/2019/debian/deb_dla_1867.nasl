# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891867");
  script_cve_id("CVE-2019-11555", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2019-08-01 02:00:14 +0000 (Thu, 01 Aug 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-18 17:01:41 +0000 (Thu, 18 Apr 2019)");

  script_name("Debian: Security Advisory (DLA-1867-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1867-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1867-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DLA-1867-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in WPA supplicant / hostapd. Some of them could only partially be mitigated, please read below for details.

CVE-2019-9495

Cache-based side-channel attack against the EAP-pwd implementation: an attacker able to run unprivileged code on the target machine (including for example javascript code in a browser on a smartphone) during the handshake could deduce enough information to discover the password in a dictionary attack.

This issue has only very partially been mitigated against by reducing measurable timing differences during private key operations. More work is required to fully mitigate this vulnerability.

CVE-2019-9497

Reflection attack against EAP-pwd server implementation: a lack of validation of received scalar and elements value in the EAP-pwd-Commit messages could have resulted in attacks that would have been able to complete EAP-pwd authentication exchange without the attacker having to know the password. This did not result in the attacker being able to derive the session key, complete the following key exchange and access the network.

CVE-2019-9498

EAP-pwd server missing commit validation for scalar/element: hostapd didn't validate values received in the EAP-pwd-Commit message, so an attacker could have used a specially crafted commit message to manipulate the exchange in order for hostapd to derive a session key from a limited set of possible values. This could have resulted in an attacker being able to complete authentication and gain access to the network.

This issue could only partially be mitigated.

CVE-2019-9499

EAP-pwd peer missing commit validation for scalar/element: wpa_supplicant didn't validate values received in the EAP-pwd-Commit message, so an attacker could have used a specially crafted commit message to manipulate the exchange in order for wpa_supplicant to derive a session key from a limited set of possible values. This could have resulted in an attacker being able to complete authentication and operate as a rogue AP.

This issue could only partially be mitigated.

CVE-2019-11555

The EAP-pwd implementation did't properly validate fragmentation reassembly state when receiving an unexpected fragment. This could have lead to a process crash due to a NULL pointer dereference.

An attacker in radio range of a station or access point with EAP-pwd support could cause a crash of the relevant process (wpa_supplicant or hostapd), ensuring a denial of service.

For Debian 8 Jessie, these problems have been fixed in version 2.3-1+deb8u8.

We recommend that you upgrade your wpa packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:2.3-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2.3-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.3-1+deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2.3-1+deb8u8", rls:"DEB8"))) {
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
