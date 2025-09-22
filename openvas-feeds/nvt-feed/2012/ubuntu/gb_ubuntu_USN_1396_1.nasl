# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840929");
  script_cve_id("CVE-2009-5029", "CVE-2010-0015", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-1659", "CVE-2011-2702", "CVE-2011-4609", "CVE-2012-0864");
  script_tag(name:"creation_date", value:"2012-03-12 07:12:00 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1396-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1396-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1396-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eglibc, glibc' package(s) announced via the USN-1396-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GNU C Library did not properly handle
integer overflows in the timezone handling code. An attacker could use
this to possibly execute arbitrary code by convincing an application
to load a maliciously constructed tzfile. (CVE-2009-5029)

It was discovered that the GNU C Library did not properly handle
passwd.adjunct.byname map entries in the Network Information Service
(NIS) code in the name service caching daemon (nscd). An attacker
could use this to obtain the encrypted passwords of NIS accounts.
This issue only affected Ubuntu 8.04 LTS. (CVE-2010-0015)

Chris Evans reported that the GNU C Library did not properly
calculate the amount of memory to allocate in the fnmatch() code. An
attacker could use this to cause a denial of service or possibly
execute arbitrary code via a maliciously crafted UTF-8 string.
This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
10.10. (CVE-2011-1071)

Tomas Hoger reported that an additional integer overflow was possible
in the GNU C Library fnmatch() code. An attacker could use this to
cause a denial of service via a maliciously crafted UTF-8 string. This
issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04. (CVE-2011-1659)

Dan Rosenberg discovered that the addmntent() function in the GNU C
Library did not report an error status for failed attempts to write to
the /etc/mtab file. This could allow an attacker to corrupt /etc/mtab,
possibly causing a denial of service or otherwise manipulate mount
options. This issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS,
Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1089)

Harald van Dijk discovered that the locale program included with the
GNU C library did not properly quote its output. This could allow a
local attacker to possibly execute arbitrary code using a crafted
localization string that was evaluated in a shell script. This
issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS and Ubuntu
10.10. (CVE-2011-1095)

It was discovered that the GNU C library loader expanded the
$ORIGIN dynamic string token when RPATH is composed entirely of this
token. This could allow an attacker to gain privilege via a setuid
program that had this RPATH value. (CVE-2011-1658)

It was discovered that the GNU C library implementation of memcpy
optimized for Supplemental Streaming SIMD Extensions 3 (SSSE3)
contained a possible integer overflow. An attacker could use this to
cause a denial of service or possibly execute arbitrary code. This
issue only affected Ubuntu 10.04 LTS. (CVE-2011-2702)

John Zimmerman discovered that the Remote Procedure Call (RPC)
implementation in the GNU C Library did not properly handle large
numbers of connections. This could allow a remote attacker to cause
a denial of service. (CVE-2011-4609)

It was discovered that the GNU C Library vfprintf() implementation
contained a possible integer overflow in the format ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'eglibc, glibc' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.11.1-0ubuntu7.10", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libc-bin", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.12.1-0ubuntu10.4", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.13-0ubuntu13.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.13-20ubuntu5.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libc6", ver:"2.7-10ubuntu8.1", rls:"UBUNTU8.04 LTS"))) {
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
