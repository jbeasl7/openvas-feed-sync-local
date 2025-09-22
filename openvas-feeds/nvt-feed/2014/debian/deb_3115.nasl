# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703115");
  script_cve_id("CVE-2014-9130");
  script_tag(name:"creation_date", value:"2014-12-28 23:00:00 +0000 (Sun, 28 Dec 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3115-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3115-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3115");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pyyaml' package(s) announced via the DSA-3115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jonathan Gray and Stanislaw Pitucha found an assertion failure in the way wrapped strings are parsed in Python-YAML, a YAML parser and emitter for Python. An attacker able to load specially crafted YAML input into an application using python-yaml could cause the application to crash.

For the stable distribution (wheezy), this problem has been fixed in version 3.10-4+deb7u1.

For the upcoming stable distribution (jessie), this problem has been fixed in version 3.11-2.

For the unstable distribution (sid), this problem has been fixed in version 3.11-2.

We recommend that you upgrade your pyyaml packages.");

  script_tag(name:"affected", value:"'pyyaml' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-yaml", ver:"3.10-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-yaml-dbg", ver:"3.10-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-yaml", ver:"3.10-4+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-yaml-dbg", ver:"3.10-4+deb7u1", rls:"DEB7"))) {
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
