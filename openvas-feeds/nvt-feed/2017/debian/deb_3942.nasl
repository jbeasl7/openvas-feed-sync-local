# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703942");
  script_cve_id("CVE-2017-11610");
  script_tag(name:"creation_date", value:"2017-08-12 22:00:00 +0000 (Sat, 12 Aug 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 16:23:44 +0000 (Thu, 31 Aug 2017)");

  script_name("Debian: Security Advisory (DSA-3942-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-3942-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3942-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3942");
  script_xref(name:"URL", value:"https://github.com/Supervisor/supervisor/issues/964");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'supervisor' package(s) announced via the DSA-3942-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Calum Hutton reported that the XML-RPC server in supervisor, a system for controlling process state, does not perform validation on requested XML-RPC methods, allowing an authenticated client to send a malicious XML-RPC request to supervisord that will run arbitrary shell commands on the server as the same user as supervisord.

The vulnerability has been fixed by disabling nested namespace lookup entirely. supervisord will now only call methods on the object registered to handle XML-RPC requests and not any child objects it may contain, possibly breaking existing setups. No publicly available plugins are currently known that use nested namespaces. Plugins that use a single namespace will continue to work as before. Details can be found on the upstream issue at [link moved to references] .

For the oldstable distribution (jessie), this problem has been fixed in version 3.0r1-1+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 3.3.1-1+deb9u1.

We recommend that you upgrade your supervisor packages.");

  script_tag(name:"affected", value:"'supervisor' package(s) on Debian 8, Debian 9.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"supervisor", ver:"3.0r1-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"supervisor", ver:"3.3.1-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"supervisor-doc", ver:"3.3.1-1+deb9u1", rls:"DEB9"))) {
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
