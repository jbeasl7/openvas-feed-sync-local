# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705049");
  script_cve_id("CVE-2021-43860", "CVE-2022-21682");
  script_tag(name:"creation_date", value:"2022-01-26 02:00:55 +0000 (Wed, 26 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 19:43:45 +0000 (Fri, 21 Jan 2022)");

  script_name("Debian: Security Advisory (DSA-5049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5049-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5049-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5049");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/flatpak");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flatpak' package(s) announced via the DSA-5049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Flatpak, an application deployment framework for desktop apps.

CVE-2021-43860

Ryan Gonzalez discovered that Flatpak didn't properly validate that the permissions displayed to the user for an app at install time match the actual permissions granted to the app at runtime. Malicious apps could therefore grant themselves permissions without the consent of the user.

CVE-2022-21682

Flatpak didn't always prevent a malicious flatpak-builder user from writing to the local filesystem.

For the stable distribution (bullseye), these problems have been fixed in version 1.10.7-0+deb11u1.

Please note that flatpak-builder also needed an update for compatibility, and is now at version 1.0.12-1+deb11u1 in bullseye.

We recommend that you upgrade your flatpak and flatpak-builder packages.

For the detailed security status of flatpak please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'flatpak' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"flatpak", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"flatpak-tests", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-flatpak-1.0", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak-dev", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak-doc", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak0", ver:"1.10.7-0+deb11u1", rls:"DEB11"))) {
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
