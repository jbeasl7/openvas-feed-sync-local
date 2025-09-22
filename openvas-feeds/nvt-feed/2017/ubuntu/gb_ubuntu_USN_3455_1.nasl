# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843342");
  script_cve_id("CVE-2016-4476", "CVE-2016-4477", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088");
  script_tag(name:"creation_date", value:"2017-10-18 14:53:52 +0000 (Wed, 18 Oct 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-01 12:00:38 +0000 (Wed, 01 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-3455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3455-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3455-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa' package(s) announced via the USN-3455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathy Vanhoef discovered that wpa_supplicant and hostapd incorrectly
handled WPA2. A remote attacker could use this issue with key
reinstallation attacks to obtain sensitive information. (CVE-2017-13077,
CVE-2017-13078, CVE-2017-13079, CVE-2017-13080, CVE-2017-13081,
CVE-2017-13082, CVE-2017-13086, CVE-2017-13087, CVE-2017-13088)

Imre Rad discovered that wpa_supplicant and hostapd incorrectly handled
invalid characters in passphrase parameters. A remote attacker could use
this issue to cause a denial of service. (CVE-2016-4476)

Imre Rad discovered that wpa_supplicant and hostapd incorrectly handled
invalid characters in passphrase parameters. A local attacker could use
this issue to cause a denial of service, or possibly execute arbitrary
code. (CVE-2016-4477)");

  script_tag(name:"affected", value:"'wpa' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:2.1-0ubuntu1.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.1-0ubuntu1.5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:2.4-0ubuntu6.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.4-0ubuntu6.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2.4-0ubuntu9.1", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.4-0ubuntu9.1", rls:"UBUNTU17.04"))) {
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
