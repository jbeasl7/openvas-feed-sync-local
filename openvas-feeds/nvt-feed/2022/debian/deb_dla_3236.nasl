# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893236");
  script_cve_id("CVE-2020-16587", "CVE-2020-16588", "CVE-2020-16589", "CVE-2021-20296", "CVE-2021-20298", "CVE-2021-20299", "CVE-2021-20300", "CVE-2021-20302", "CVE-2021-20303", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476", "CVE-2021-3477", "CVE-2021-3478", "CVE-2021-3479", "CVE-2021-3598", "CVE-2021-3605", "CVE-2021-3933", "CVE-2021-3941", "CVE-2021-45942");
  script_tag(name:"creation_date", value:"2022-12-12 02:00:25 +0000 (Mon, 12 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 17:03:17 +0000 (Tue, 22 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-3236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3236-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3236-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openexr");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openexr' package(s) announced via the DLA-3236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been found in OpenEXR, command-line tools and a library for the OpenEXR image format. Buffer overflows or out-of-bound reads could lead to a denial of service (application crash) if a malformed image file is processed.

For Debian 10 buster, these problems have been fixed in version 2.2.1-4.1+deb10u2.

We recommend that you upgrade your openexr packages.

For the detailed security status of openexr please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openexr' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr-dev", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr23", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr-doc", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
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
