# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704487");
  script_cve_id("CVE-2019-12735");
  script_tag(name:"creation_date", value:"2019-07-25 02:00:12 +0000 (Thu, 25 Jul 2019)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-05 19:22:55 +0000 (Wed, 05 Jun 2019)");

  script_name("Debian: Security Advisory (DSA-4487-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4487-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/DSA-4487-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4487");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'neovim' package(s) announced via the DSA-4487-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"User Arminius discovered a vulnerability in Vim, an enhanced version of the standard UNIX editor Vi (Vi IMproved), which also affected the Neovim fork, an extensible editor focused on modern code and features:

Editors typically provide a way to embed editor configuration commands (aka modelines) which are executed once a file is opened, while harmful commands are filtered by a sandbox mechanism. It was discovered that the source command (used to include and execute another file) was not filtered, allowing shell command execution with a carefully crafted file opened in Neovim.

For the oldstable distribution (stretch), this problem has been fixed in version 0.1.7-4+deb9u1.

We recommend that you upgrade your neovim packages.");

  script_tag(name:"affected", value:"'neovim' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"neovim", ver:"0.1.7-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"neovim-runtime", ver:"0.1.7-4+deb9u1", rls:"DEB9"))) {
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
