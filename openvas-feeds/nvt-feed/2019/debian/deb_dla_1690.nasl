# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891690");
  script_cve_id("CVE-2019-6256", "CVE-2019-7314");
  script_tag(name:"creation_date", value:"2019-02-25 23:00:00 +0000 (Mon, 25 Feb 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-04 17:19:23 +0000 (Mon, 04 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-1690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1690-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1690-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'liblivemedia' package(s) announced via the DLA-1690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in liblivemedia, the LIVE555 RTSP server library:

CVE-2019-6256

liblivemedia servers with RTSP-over-HTTP tunneling enabled are vulnerable to an invalid function pointer dereference. This issue might happen during error handling when processing two GET and POST requests being sent with identical x-sessioncookie within the same TCP session and might be leveraged by remote attackers to cause DoS.

CVE-2019-7314

liblivemedia servers with RTSP-over-HTTP tunneling enabled are affected by a use-after-free vulnerability. This vulnerability might be triggered by remote attackers to cause DoS (server crash) or possibly unspecified other impact.

For Debian 8 Jessie, these problems have been fixed in version 2014.01.13-1+deb8u2.

We recommend that you upgrade your liblivemedia packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'liblivemedia' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libbasicusageenvironment0", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgroupsock1", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblivemedia-dev", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblivemedia23", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libusageenvironment1", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"livemedia-utils", ver:"2014.01.13-1+deb8u2", rls:"DEB8"))) {
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
