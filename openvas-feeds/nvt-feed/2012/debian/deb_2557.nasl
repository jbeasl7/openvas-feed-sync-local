# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72474");
  script_cve_id("CVE-2012-4445");
  script_tag(name:"creation_date", value:"2012-10-13 06:34:33 +0000 (Sat, 13 Oct 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2557-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2557-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2557-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2557");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hostapd' package(s) announced via the DSA-2557-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timo Warns discovered that the internal authentication server of hostapd, a user space IEEE 802.11 AP and IEEE 802.1X/WPA/WPA2/EAP Authenticator, is vulnerable to a buffer overflow when processing fragmented EAP-TLS messages. As a result, an internal overflow checking routine terminates the process. An attacker can abuse this flaw to conduct denial of service attacks via crafted EAP-TLS messages prior to any authentication.

For the stable distribution (squeeze), this problem has been fixed in version 1:0.6.10-2+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem will be fixed soon.

We recommend that you upgrade your hostapd packages.");

  script_tag(name:"affected", value:"'hostapd' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"1:0.6.10-2+squeeze1", rls:"DEB6"))) {
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
