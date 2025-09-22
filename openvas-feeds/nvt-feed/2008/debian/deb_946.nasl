# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56531");
  script_cve_id("CVE-2005-4158", "CVE-2006-0151");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-946-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-946-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-946-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-946");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DSA-946-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The former correction to vulnerabilities in the sudo package worked fine but were too strict for some environments. Therefore we have reviewed the changes again and allowed some environment variables to go back into the privileged execution environment. Hence, this update.

The configuration option 'env_reset' is now activated by default. It will preserve only the environment variables HOME, LOGNAME, PATH, SHELL, TERM, DISPLAY, XAUTHORITY, XAUTHORIZATION, LANG, LANGUAGE, LC_*, and USER in addition to the separate SUDO_* variables.

For completeness please find below the original advisory text:

It has been discovered that sudo, a privileged program, that provides limited super user privileges to specific users, passes several environment variables to the program that runs with elevated privileges. In the case of include paths (e.g. for Perl, Python, Ruby or other scripting languages) this can cause arbitrary code to be executed as privileged user if the attacker points to a manipulated version of a system library.

This update alters the former behaviour of sudo and limits the number of supported environment variables to LC_*, LANG, LANGUAGE and TERM. Additional variables are only passed through when set as env_check in /etc/sudoers, which might be required for some scripts to continue to work.

For the old stable distribution (woody) this problem has been fixed in version 1.6.6-1.6.

For the stable distribution (sarge) this problem has been fixed in version 1.6.8p7-1.4.

For the unstable distribution (sid) the same behaviour will be implemented soon.

We recommend that you upgrade your sudo package. For unstable 'Defaults = env_reset' need to be added to /etc/sudoers manually.");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 3.0, Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.6.6-1.6", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.6.8p7-1.4", rls:"DEB3.1"))) {
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
