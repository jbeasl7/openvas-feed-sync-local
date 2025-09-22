# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704200");
  script_cve_id("CVE-2018-10380");
  script_tag(name:"creation_date", value:"2018-05-13 22:00:00 +0000 (Sun, 13 May 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 18:32:02 +0000 (Tue, 12 Jun 2018)");

  script_name("Debian: Security Advisory (DSA-4200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4200-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4200-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4200");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kwallet-pam");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kwallet-pam' package(s) announced via the DSA-4200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabian Vogt discovered that incorrect permission handling in the PAM module of the KDE Wallet could allow an unprivileged local user to gain ownership of arbitrary files.

For the stable distribution (stretch), this problem has been fixed in version 5.8.4-1+deb9u2.

We recommend that you upgrade your kwallet-pam packages.

For the detailed security status of kwallet-pam please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kwallet-pam' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-kwallet-common", ver:"5.8.4-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-kwallet4", ver:"5.8.4-1+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-kwallet5", ver:"5.8.4-1+deb9u2", rls:"DEB9"))) {
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
