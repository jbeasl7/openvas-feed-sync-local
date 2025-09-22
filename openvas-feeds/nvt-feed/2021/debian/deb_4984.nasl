# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704984");
  script_cve_id("CVE-2021-41133");
  script_tag(name:"creation_date", value:"2021-10-15 01:00:10 +0000 (Fri, 15 Oct 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 19:57:20 +0000 (Fri, 15 Oct 2021)");

  script_name("Debian: Security Advisory (DSA-4984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-4984-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4984-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4984");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/security/advisories/GHSA-67h7-w3jq-vh4q");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/flatpak");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flatpak' package(s) announced via the DSA-4984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that sandbox restrictions in Flatpak, an application deployment framework for desktop apps, could be bypassed for a Flatpak app with direct access to AF_UNIX sockets, by manipulating the VFS using mount-related syscalls that are not blocked by Flatpak's denylist seccomp filter.

Details can be found in the upstream advisory at [link moved to references]

For the stable distribution (bullseye), this problem has been fixed in version 1.10.5-0+deb11u1.

We recommend that you upgrade your flatpak packages.

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

  if(!isnull(res = isdpkgvuln(pkg:"flatpak", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"flatpak-tests", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gir1.2-flatpak-1.0", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak-dev", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak-doc", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflatpak0", ver:"1.10.5-0+deb11u1", rls:"DEB11"))) {
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
