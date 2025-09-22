# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704389");
  script_cve_id("CVE-2018-20340");
  script_tag(name:"creation_date", value:"2019-02-10 23:00:00 +0000 (Sun, 10 Feb 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 16:09:09 +0000 (Wed, 27 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-4389-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4389-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4389-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4389");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libu2f-host");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libu2f-host' package(s) announced via the DSA-4389-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Reitter discovered that libu2f-host, a library implementing the host-side of the U2F protocol, failed to properly check for a buffer overflow. This would allow an attacker with a custom made malicious USB device masquerading as a security key, and physical access to a computer where PAM U2F or an application with libu2f-host integrated, to potentially execute arbitrary code on that computer.

For the stable distribution (stretch), this problem has been fixed in version 1.1.2-2+deb9u1.

We recommend that you upgrade your libu2f-host packages.

For the detailed security status of libu2f-host please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libu2f-host' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libu2f-host-dev", ver:"1.1.2-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libu2f-host0", ver:"1.1.2-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u2f-host", ver:"1.1.2-2+deb9u1", rls:"DEB9"))) {
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
