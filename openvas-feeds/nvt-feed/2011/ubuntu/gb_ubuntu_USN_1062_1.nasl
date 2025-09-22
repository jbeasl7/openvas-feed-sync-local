# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840584");
  script_cve_id("CVE-2010-4022", "CVE-2011-0281", "CVE-2011-0282");
  script_tag(name:"creation_date", value:"2011-02-16 13:19:17 +0000 (Wed, 16 Feb 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-1062-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|8\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1062-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1062-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-1062-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Keiichi Mori discovered that the MIT krb5 KDC database propagation
daemon (kpropd) is vulnerable to a denial of service attack due
to improper logic when a worker child process exited because
of invalid network input. This could only occur when kpropd is
running in standalone mode, kpropd was not affected when running in
incremental propagation mode ('iprop') or as an inetd server. This
issue only affects Ubuntu 9.10, Ubuntu 10.04 LTS, and Ubuntu
10.10. (CVE-2010-4022)

Kevin Longfellow and others discovered that the MIT krb5 Key
Distribution Center (KDC) daemon is vulnerable to denial of service
attacks when using an LDAP back end due to improper handling of
network input. (CVE-2011-0281, CVE-2011-0282)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.1+dfsg-2ubuntu0.6", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.1+dfsg-2ubuntu0.6", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.1+dfsg-5ubuntu0.4", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.1+dfsg-5ubuntu0.4", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.3~beta1-2ubuntu1.8", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.7dfsg~beta3-1ubuntu0.9", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.7dfsg~beta3-1ubuntu0.9", rls:"UBUNTU9.10"))) {
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
