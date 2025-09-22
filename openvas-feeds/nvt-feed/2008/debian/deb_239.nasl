# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53316");
  script_cve_id("CVE-2002-1393");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-239");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-239");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-239");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kdesdk' package(s) announced via the DSA-239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The KDE team discovered several vulnerabilities in the K Desktop Environment. In some instances KDE fails to properly quote parameters of instructions passed to a command shell for execution. These parameters may incorporate data such as URLs, filenames and e-mail addresses, and this data may be provided remotely to a victim in an e-mail, a webpage or files on a network filesystem or other untrusted source.

By carefully crafting such data an attacker might be able to execute arbitrary commands on a vulnerable system using the victim's account and privileges. The KDE Project is not aware of any existing exploits of these vulnerabilities. The patches also provide better safe guards and check data from untrusted sources more strictly in multiple places.

For the current stable distribution (woody), these problems have been fixed in version 2.2.2-3.2.

The old stable distribution (potato) does not contain KDE packages.

For the unstable distribution (sid), these problems will most probably not be fixed but new packages for KDE 3.1 for sid are expected for this year.

We recommend that you upgrade your KDE packages.");

  script_tag(name:"affected", value:"'kdesdk' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kapptemplate", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kbabel", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kbabel-dev", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdepalettes", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesdk", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesdk-doc", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesdk-scripts", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kexample", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmtrace", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kspy", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kstartperf", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poxml", ver:"2.2.2-3.2", rls:"DEB3.0"))) {
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
