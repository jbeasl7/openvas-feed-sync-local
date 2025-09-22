# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71502");
  script_cve_id("CVE-2012-0049", "CVE-2012-3436");
  script_tag(name:"creation_date", value:"2012-08-10 07:21:14 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-09 22:15:48 +0000 (Sat, 09 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-2524-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2524-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2524-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2524");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openttd' package(s) announced via the DSA-2524-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two denial of service vulnerabilities have been discovered in the server component of OpenTTD, a free reimplementation of Transport Tycoon Deluxe.

For the stable distribution (squeeze), this problem has been fixed in version 1.0.4-6.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your openttd packages.");

  script_tag(name:"affected", value:"'openttd' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openttd", ver:"1.0.4-6", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openttd-data", ver:"1.0.4-6", rls:"DEB6"))) {
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
