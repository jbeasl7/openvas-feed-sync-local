# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704898");
  script_cve_id("CVE-2020-12695", "CVE-2021-0326", "CVE-2021-27803");
  script_tag(name:"creation_date", value:"2021-04-23 03:00:18 +0000 (Fri, 23 Apr 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-05 21:38:26 +0000 (Fri, 05 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4898-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4898-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4898");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpa");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-4898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in wpa_supplicant and hostapd.

CVE-2020-12695

It was discovered that hostapd does not properly handle UPnP subscribe messages under certain conditions, allowing an attacker to cause a denial of service.

CVE-2021-0326

It was discovered that wpa_supplicant does not properly process P2P (Wi-Fi Direct) group information from active group owners. An attacker within radio range of the device running P2P could take advantage of this flaw to cause a denial of service or potentially execute arbitrary code.

CVE-2021-27803

It was discovered that wpa_supplicant does not properly process P2P (Wi-Fi Direct) provision discovery requests. An attacker within radio range of the device running P2P could take advantage of this flaw to cause a denial of service or potentially execute arbitrary code.

For the stable distribution (buster), these problems have been fixed in version 2:2.7+git20190128+0c1e29f-6+deb10u3.

We recommend that you upgrade your wpa packages.

For the detailed security status of wpa please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2:2.7+git20190128+0c1e29f-6+deb10u3", rls:"DEB10"))) {
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
