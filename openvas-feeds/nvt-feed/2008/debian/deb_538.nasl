# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53228");
  script_cve_id("CVE-2004-0792");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-538)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-538");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-538");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-538");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rsync' package(s) announced via the DSA-538 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The rsync developers have discovered a security related problem in rsync, a fast remote file copy program, which offers an attacker to access files outside of the defined directory. To exploit this path-sanitizing bug, rsync has to run in daemon mode with the chroot option being disabled. It does not affect the normal send/receive filenames that specify what files should be transferred. It does affect certain option paths that cause auxiliary files to be read or written.

For the stable distribution (woody) this problem has been fixed in version 2.5.5-0.6.

For the unstable distribution (sid) this problem has been fixed in version 2.6.2-3.

We recommend that you upgrade your rsync package.");

  script_tag(name:"affected", value:"'rsync' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rsync", ver:"2.5.5-0.6", rls:"DEB3.0"))) {
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
