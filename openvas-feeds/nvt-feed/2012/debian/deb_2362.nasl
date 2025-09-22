# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70574");
  script_cve_id("CVE-2011-1159", "CVE-2011-4578");
  script_tag(name:"creation_date", value:"2012-02-11 07:34:11 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2362-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2362-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2362");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'acpid' package(s) announced via the DSA-2362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in the ACPI Daemon, the Advanced Configuration and Power Interface event daemon:

CVE-2011-1159

Vasiliy Kulikov of OpenWall discovered that the socket handling is vulnerable to denial of service.

CVE-2011-2777

Oliver-Tobias Ripka discovered that incorrect process handling in the Debian-specific powerbtn.sh script could lead to local privilege escalation. This issue doesn't affect oldstable. The script is only shipped as an example in /usr/share/doc/acpid/examples. See /usr/share/doc/acpid/README.Debian for details.

CVE-2011-4578

Helmut Grohne and Michael Biebl discovered that acpid sets a umask of 0 when executing scripts, which could result in local privilege escalation.

For the oldstable distribution (lenny), this problem has been fixed in version 1.0.8-1lenny4.

For the stable distribution (squeeze), this problem has been fixed in version 1:2.0.7-1squeeze3.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your acpid packages.");

  script_tag(name:"affected", value:"'acpid' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"acpid", ver:"1.0.8-1lenny4", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"acpid", ver:"1:2.0.7-1squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kacpimon", ver:"1:2.0.7-1squeeze3", rls:"DEB6"))) {
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
