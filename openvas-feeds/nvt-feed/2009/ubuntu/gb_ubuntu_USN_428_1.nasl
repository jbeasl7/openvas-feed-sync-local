# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840150");
  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-428-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS|6\.10)");

  script_xref(name:"Advisory-ID", value:"USN-428-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-428-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws have been found that could be used to perform Cross-site
scripting attacks. A malicious web site could exploit these to modify
the contents or steal confidential data (such as passwords) from other
opened web pages. (CVE-2006-6077, CVE-2007-0780, CVE-2007-0800,
CVE-2007-0981, CVE-2007-0995, CVE-2007-0996)

The SSLv2 protocol support in the NSS library did not sufficiently
check the validity of public keys presented with a SSL certificate. A
malicious SSL web site using SSLv2 could potentially exploit this to
execute arbitrary code with the user's privileges. (CVE-2007-0008)

The SSLv2 protocol support in the NSS library did not sufficiently
verify the validity of client master keys presented in an SSL client
certificate. A remote attacker could exploit this to execute arbitrary
code in a server application that uses the NSS library.
(CVE-2007-0009)

Various flaws have been reported that could allow an attacker to
execute arbitrary code with user privileges by tricking the user into
opening a malicious web page. (CVE-2007-0775, CVE-2007-0776,
CVE-2007-0777, CVE-2007-1092)

Two web pages could collide in the disk cache with the result that
depending on order loaded the end of the longer document could be
appended to the shorter when the shorter one was reloaded from the
cache. It is possible a determined hacker could construct a targeted
attack to steal some sensitive data from a particular web page. The
potential victim would have to be already logged into the targeted
service (or be fooled into doing so) and then visit the malicious
site. (CVE-2007-0778)

David Eckel reported that browser UI elements--such as the host name
and security indicators--could be spoofed by using custom cursor
images and a specially crafted style sheet. (CVE-2007-0779)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.5.10.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"1.5.dfsg+1.5.0.10-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.2+0dfsg-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2.0.0.2+0dfsg-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2.0.0.2+0dfsg-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
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
