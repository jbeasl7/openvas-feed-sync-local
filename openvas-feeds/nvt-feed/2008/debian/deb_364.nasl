# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53653");
  script_cve_id("CVE-2003-0620", "CVE-2003-0645");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-364");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-364");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-364");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'man-db' package(s) announced via the DSA-364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"man-db provides the standard man(1) command on Debian systems. During configuration of this package, the administrator is asked whether man(1) should run setuid to a dedicated user ('man') in order to provide a shared cache of preformatted manual pages. The default is for man(1) NOT to be setuid, and in this configuration no known vulnerability exists. However, if the user explicitly requests setuid operation, a local attacker could exploit either of the following bugs to execute arbitrary code as the 'man' user.

Again, these vulnerabilities do not affect the default configuration, where man is not setuid.

CAN-2003-0620: Multiple buffer overflows in man-db 2.4.1 and earlier, when installed setuid, allow local users to gain privileges via (1) MANDATORY_MANPATH, MANPATH_MAP, and MANDB_MAP arguments to add_to_dirlist in manp.c, (2) a long pathname to ult_src in ult_src.c, (3) a long .so argument to test_for_include in ult_src.c, (4) a long MANPATH environment variable, or (5) a long PATH environment variable.

CAN-2003-0645: Certain DEFINE directives in ~/.manpath, which contained commands to be executed, would be honored even when running setuid, allowing any user to execute commands as the 'man' user.

For the current stable distribution (woody), these problems have been fixed in version 2.3.20-18.woody.4.

For the unstable distribution (sid), these problems have been fixed in version 2.4.1-13.

We recommend that you update your man-db package.");

  script_tag(name:"affected", value:"'man-db' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"man-db", ver:"2.3.20-18.woody.4", rls:"DEB3.0"))) {
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
