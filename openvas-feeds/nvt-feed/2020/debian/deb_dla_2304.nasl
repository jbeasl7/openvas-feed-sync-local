# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892304");
  script_cve_id("CVE-2015-9542");
  script_tag(name:"creation_date", value:"2020-08-02 03:00:10 +0000 (Sun, 02 Aug 2020)");
  script_version("2024-02-01T14:37:11+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:11 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 16:20:56 +0000 (Tue, 25 Feb 2020)");

  script_name("Debian: Security Advisory (DLA-2304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2304-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/DLA-2304-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libpam-radius-auth");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-radius-auth' package(s) announced via the DLA-2304-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"`add_password` in pam_radius_auth.c in pam_radius 1.4.0 does not correctly check the length of the input password, and is vulnerable to a stack-based buffer overflow during memcpy(). An attacker could send a crafted password to an application (loading the pam_radius library) and crash it. Arbitrary code execution might be possible, depending on the application, C library, compiler, and other factors.

For Debian 9 stretch, this problem has been fixed in version 1.3.16-5+deb9u1.

We recommend that you upgrade your libpam-radius-auth packages.

For the detailed security status of libpam-radius-auth please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libpam-radius-auth' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-radius-auth", ver:"1.3.16-5+deb9u1", rls:"DEB9"))) {
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
