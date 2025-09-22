# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703397");
  script_cve_id("CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-4144", "CVE-2015-4145", "CVE-2015-4146", "CVE-2015-5310", "CVE-2015-5314", "CVE-2015-5315", "CVE-2015-5316", "CVE-2015-8041");
  script_tag(name:"creation_date", value:"2015-11-09 23:00:00 +0000 (Mon, 09 Nov 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-21 13:06:13 +0000 (Wed, 21 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-3397-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");

  script_xref(name:"Advisory-ID", value:"DSA-3397-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3397-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3397");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-3397-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in wpa_supplicant and hostapd. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-4141

Kostya Kortchinsky of the Google Security Team discovered a vulnerability in the WPS UPnP function with HTTP chunked transfer encoding which may result in a denial of service.

CVE-2015-4142

Kostya Kortchinsky of the Google Security Team discovered a vulnerability in the WMM Action frame processing which may result in a denial of service.

CVE-2015-4143

CVE-2015-4144

CVE-2015-4145

CVE-2015-4146

Kostya Kortchinsky of the Google Security Team discovered that EAP-pwd payload is not properly validated which may result in a denial of service.

CVE-2015-5310

Jouni Malinen discovered a flaw in the WMM Sleep Mode Response frame processing. A remote attacker can take advantage of this flaw to mount a denial of service.

CVE-2015-5314

CVE-2015-5315

Jouni Malinen discovered a flaw in the handling of EAP-pwd messages which may result in a denial of service.

CVE-2015-5316

Jouni Malinen discovered a flaw in the handling of EAP-pwd Confirm messages which may result in a denial of service.

CVE-2015-8041

Incomplete WPS and P2P NFC NDEF record payload length validation may result in a denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 1.0-3+deb7u3. The oldstable distribution (wheezy) is only affected by CVE-2015-4141, CVE-2015-4142, CVE-2015-4143 and CVE-2015-8041.

For the stable distribution (jessie), these problems have been fixed in version 2.3-1+deb8u3.

We recommend that you upgrade your wpa packages.");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 7, Debian 8.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:1.0-3+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"1.0-3+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"1.0-3+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"1.0-3+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:2.3-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2.3-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2.3-1+deb8u3", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2.3-1+deb8u3", rls:"DEB8"))) {
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
