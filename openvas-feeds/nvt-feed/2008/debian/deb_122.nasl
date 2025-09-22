# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53398");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0059");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:16:30 +0000 (Fri, 02 Feb 2024)");
  script_name("Debian Security Advisory DSA 122-1 (zlib, various)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20122-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4267");
  script_tag(name:"insight", value:"The compression library zlib has a flaw in which it attempts to free
memory more than once under certain conditions. This can possibly be
exploited to run arbitrary code in a program that includes zlib. If a
network application running as root is linked to zlib, this could
potentially lead to a remote root compromise. No exploits are known at
this time. This vulnerability is assigned the CVE candidate name of
CVE-2002-0059.

The zlib vulnerability is fixed in the Debian zlib package version
1.1.3-5.1. A number of programs either link statically to zlib or include
a private copy of zlib code. These programs must also be upgraded
to eliminate the zlib vulnerability. The affected packages and fixed
versions follow:
amaya 2.4-1potato1
dictd 1.4.9-9potato1
erlang 49.1-10.1
freeamp 2.0.6-2.1
mirrordir 0.10.48-2.1
ppp 2.3.11-1.5
rsync 2.3.2-1.6
vrweb 1.5-5.1

Those using the pre-release (testing) version of Debian should upgrade
to zlib 1.1.3-19.1 or a later version. Note that since this version of
Debian has not yet been released it may not be available immediately for
all architectures. Debian 2.2 (potato) is the latest supported release.");

  script_tag(name:"solution", value:"We recommend that you upgrade your packages immediately. Note that you");
  script_tag(name:"summary", value:"The remote host is missing an update to zlib, various
announced via advisory DSA 122-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"erlang-base", ver:"49.1-10.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-erl", ver:"49.1-10.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang-java", ver:"49.1-10.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"freeamp-doc", ver:"2.0.6-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"amaya", ver:"2.4-1potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dict", ver:"1.4.9-9potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dictd", ver:"1.4.9-9potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mirrordir", ver:"0.10.48-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ppp", ver:"2.3.11-1.5", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rsync", ver:"2.3.2-1.6", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vrweb", ver:"1.5-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib-bin", ver:"1.1.3-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1g-dev", ver:"1.1.3-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1g", ver:"1.1.3-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"erlang", ver:"49.1-10.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"freeamp", ver:"2.0.6-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreeamp-alsa", ver:"2.0.6-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libfreeamp-esound", ver:"2.0.6-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1-altdev", ver:"1.1.3-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zlib1", ver:"1.1.3-5.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
