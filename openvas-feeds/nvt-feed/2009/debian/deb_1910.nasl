# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66056");
  script_cve_id("CVE-2009-2942");
  script_tag(name:"creation_date", value:"2009-10-19 19:50:22 +0000 (Mon, 19 Oct 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1910-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(4|5)");

  script_xref(name:"Advisory-ID", value:"DSA-1910-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1910-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1910");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-ocaml' package(s) announced via the DSA-1910-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mysql-ocaml, OCaml bindings for MySql, was missing a function to call mysql_real_escape_string(). This is needed, because mysql_real_escape_string() honours the charset of the connection and prevents insufficient escaping, when certain multibyte character encodings are used. The added function is called real_escape() and takes the established database connection as a first argument. The old escape_string() was kept for backwards compatibility.

Developers using these bindings are encouraged to adjust their code to use the new function.

For the oldstable distribution (etch), this problem has been fixed in version 1.0.4-2+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.0.4-4+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your mysql-ocaml packages.");

  script_tag(name:"affected", value:"'mysql-ocaml' package(s) on Debian 4, Debian 5.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysql-ocaml", ver:"1.0.4-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysql-ocaml-dev", ver:"1.0.4-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysql-ocaml", ver:"1.0.4-4+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysql-ocaml-dev", ver:"1.0.4-4+lenny1", rls:"DEB5"))) {
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
