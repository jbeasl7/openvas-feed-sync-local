# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704430");
  script_cve_id("CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2019-04-13 02:00:11 +0000 (Sat, 13 Apr 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-18 17:01:41 +0000 (Thu, 18 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-4430-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4430-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4430-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4430");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpa");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-4430-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathy Vanhoef (NYUAD) and Eyal Ronen (Tel Aviv University & KU Leuven) found multiple vulnerabilities in the WPA implementation found in wpa_supplication (station) and hostapd (access point). These vulnerabilities are also collectively known as Dragonblood.

CVE-2019-9495

Cache-based side-channel attack against the EAP-pwd implementation: an attacker able to run unprivileged code on the target machine (including for example javascript code in a browser on a smartphone) during the handshake could deduce enough information to discover the password in a dictionary attack.

CVE-2019-9497

Reflection attack against EAP-pwd server implementation: a lack of validation of received scalar and elements value in the EAP-pwd-Commit messages could result in attacks that would be able to complete EAP-pwd authentication exchange without the attacker having to know the password. This does not result in the attacker being able to derive the session key, complete the following key exchange and access the network.

CVE-2019-9498

EAP-pwd server missing commit validation for scalar/element: hostapd doesn't validate values received in the EAP-pwd-Commit message, so an attacker could use a specially crafted commit message to manipulate the exchange in order for hostapd to derive a session key from a limited set of possible values. This could result in an attacker being able to complete authentication and gain access to the network.

CVE-2019-9499

EAP-pwd peer missing commit validation for scalar/element: wpa_supplicant doesn't validate values received in the EAP-pwd-Commit message, so an attacker could use a specially crafted commit message to manipulate the exchange in order for wpa_supplicant to derive a session key from a limited set of possible values. This could result in an attacker being able to complete authentication and operate as a rogue AP.

Note that the Dragonblood moniker also applies to CVE-2019-9494 and CVE-2014-9496 which are vulnerabilities in the SAE protocol in WPA3. SAE is not enabled in Debian stretch builds of wpa, which is thus not vulnerable by default.

Due to the complexity of the backporting process, the fix for these vulnerabilities are partial. Users are advised to use strong passwords to prevent dictionary attacks or use a 2.7-based version from stretch-backports (version above 2:2.7+git20190128+0c1e29f-4).

For the stable distribution (stretch), these problems have been fixed in version 2:2.4-1+deb9u3.

We recommend that you upgrade your wpa packages.

For the detailed security status of wpa please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.4-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.4-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.4-1+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2:2.4-1+deb9u3", rls:"DEB9"))) {
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
