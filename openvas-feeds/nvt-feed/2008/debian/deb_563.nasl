# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53256");
  script_cve_id("CVE-2004-0884");
  script_tag(name:"creation_date", value:"2008-01-17 21:45:44 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-563-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-563-3");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-563-3");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-563");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl' package(s) announced via the DSA-563-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This advisory is an addition to DSA 563-1 and 563-2 which weren't able to supersede the library on sparc and arm due to a different version number for them in the stable archive. Other architectures were updated properly. Another problem was reported in connection with sendmail, though, which should be fixed with this update as well.

For the stable distribution (woody) this problem has been fixed in version 1.5.27-3.1woody5.

For reference the advisory text follows:

A vulnerability has been discovered in the Cyrus implementation of the SASL library, the Simple Authentication and Security Layer, a method for adding authentication support to connection-based protocols. The library honors the environment variable SASL_PATH blindly, which allows a local user to link against a malicious library to run arbitrary code with the privileges of a setuid or setgid application.

For the unstable distribution (sid) this problem has been fixed in version 1.5.28-6.2 of cyrus-sasl and in version 2.1.19-1.3 of cyrus-sasl2.

We recommend that you upgrade your libsasl packages.");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsasl-dev", ver:"1.5.27-3.1woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl-digestmd5-plain", ver:"1.5.27-3.1woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl-modules-plain", ver:"1.5.27-3.1woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsasl7", ver:"1.5.27-3.1woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sasl-bin", ver:"1.5.27-3.1woody5", rls:"DEB3.0"))) {
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
