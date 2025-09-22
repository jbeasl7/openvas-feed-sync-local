# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891399");
  script_cve_id("CVE-2015-7519", "CVE-2018-12029");
  script_tag(name:"creation_date", value:"2018-07-09 22:00:00 +0000 (Mon, 09 Jul 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-23 15:56:39 +0000 (Thu, 23 Aug 2018)");

  script_name("Debian: Security Advisory (DLA-1399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1399-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1399-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-passenger' package(s) announced via the DLA-1399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two flaws were discovered in ruby-passenger for Ruby Rails and Rack support that allowed attackers to spoof HTTP headers or exploit a race condition which made privilege escalation under certain conditions possible.

CVE-2015-7519

Remote attackers could spoof headers passed to applications by using an underscore character instead of a dash character in an HTTP header as demonstrated by an X_User header.

CVE-2018-12029

A vulnerability was discovered by the Pulse Security team. It was exploitable only when running a non-standard passenger_instance_registry_dir, via a race condition where after a file was created, there was a window in which it could be replaced with a symlink before it was chowned via the path and not the file descriptor. If the symlink target was to a file which would be executed by root such as root's crontab file, then privilege escalation was possible. This is now mitigated by using fchown().

For Debian 8 Jessie, these problems have been fixed in version 4.0.53-1+deb8u1.

We recommend that you upgrade your ruby-passenger packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-passenger' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-passenger", ver:"4.0.53-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-passenger", ver:"4.0.53-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby-passenger-doc", ver:"4.0.53-1+deb8u1", rls:"DEB8"))) {
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
