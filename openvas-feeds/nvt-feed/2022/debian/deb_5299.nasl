# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705299");
  script_cve_id("CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3598", "CVE-2021-3605", "CVE-2021-3933", "CVE-2021-3941", "CVE-2021-45942");
  script_tag(name:"creation_date", value:"2022-12-12 02:00:26 +0000 (Mon, 12 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 16:45:41 +0000 (Mon, 04 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-5299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5299-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5299-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5299");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openexr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openexr' package(s) announced via the DSA-5299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been found in OpenEXR, command-line tools and a library for the OpenEXR image format. Buffer overflows or out-of-bound reads could lead to a denial of service (application crash) if a malformed image file is processed.

For the stable distribution (bullseye), these problems have been fixed in version 2.5.4-2+deb11u1.

We recommend that you upgrade your openexr packages.

For the detailed security status of openexr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openexr' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr-dev", ver:"2.5.4-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr25", ver:"2.5.4-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.5.4-2+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr-doc", ver:"2.5.4-2+deb11u1", rls:"DEB11"))) {
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
