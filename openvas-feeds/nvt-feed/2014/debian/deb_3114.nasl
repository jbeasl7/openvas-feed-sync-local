# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703114");
  script_cve_id("CVE-2014-7209");
  script_tag(name:"creation_date", value:"2014-12-28 23:00:00 +0000 (Sun, 28 Dec 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3114-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3114-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3114");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mime-support' package(s) announced via the DSA-3114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timothy D. Morgan discovered that run-mailcap, an utility to execute programs via entries in the mailcap file, is prone to shell command injection via shell meta-characters in filenames. In specific scenarios this flaw could allow an attacker to remotely execute arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 3.52-1+deb7u1.

For the upcoming stable distribution (jessie) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your mime-support packages.");

  script_tag(name:"affected", value:"'mime-support' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"mime-support", ver:"3.52-1+deb7u1", rls:"DEB7"))) {
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
