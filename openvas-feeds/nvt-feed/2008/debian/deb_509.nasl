# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53199");
  script_cve_id("CVE-2004-0395");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-509");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-509");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-509");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gatos' package(s) announced via the DSA-509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Kemp discovered a vulnerability in xatitv, one of the programs in the gatos package, which is used to display video with certain ATI video cards.

xatitv is installed setuid root in order to gain direct access to the video hardware. It normally drops root privileges after successfully initializing itself. However, if initialization fails due to a missing configuration file, root privileges are not dropped, and xatitv executes the system(3) function to launch its configuration program without sanitizing user-supplied environment variables.

By exploiting this vulnerability, a local user could gain root privileges if the configuration file does not exist. However, a default configuration file is supplied with the package, and so this vulnerability is not exploitable unless this file is removed by the administrator.

For the current stable distribution (woody) this problem has been fixed in version 0.0.5-6woody1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you update your gatos package.");

  script_tag(name:"affected", value:"'gatos' package(s) on Debian 3.0.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"gatos", ver:"0.0.5-6woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgatos-dev", ver:"0.0.5-6woody1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgatos0", ver:"0.0.5-6woody1", rls:"DEB3.0"))) {
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
