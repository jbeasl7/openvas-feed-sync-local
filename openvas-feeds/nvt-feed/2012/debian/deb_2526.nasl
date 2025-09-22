# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71822");
  script_cve_id("CVE-2012-3461");
  script_tag(name:"creation_date", value:"2012-08-30 15:32:41 +0000 (Thu, 30 Aug 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2526-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2526-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2526-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2526");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libotr' package(s) announced via the DSA-2526-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Just Ferguson discovered that libotr, an off-the-record (OTR) messaging library, can be forced to perform zero-length allocations for heap buffers that are used in base64 decoding routines. An attacker can exploit this flaw by sending crafted messages to an application that is using libotr to perform denial of service attacks or potentially execute arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in version 3.2.0-2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in version 3.2.1-1.

For the unstable distribution (sid), this problem has been fixed in version 3.2.1-1.

We recommend that you upgrade your libotr packages.");

  script_tag(name:"affected", value:"'libotr' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libotr2", ver:"3.2.0-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotr2-bin", ver:"3.2.0-2+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libotr2-dev", ver:"3.2.0-2+squeeze1", rls:"DEB6"))) {
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
