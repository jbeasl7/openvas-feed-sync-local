# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840405");
  script_cve_id("CVE-2010-0283", "CVE-2010-0628");
  script_tag(name:"creation_date", value:"2010-03-31 12:20:46 +0000 (Wed, 31 Mar 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-916-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.10");

  script_xref(name:"Advisory-ID", value:"USN-916-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-916-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-916-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Emmanuel Bouillon discovered that Kerberos did not correctly handle
certain message types. An unauthenticated remote attacker could send
specially crafted traffic to cause the KDC to crash, leading to a denial
of service. (CVE-2010-0283)

Nalin Dahyabhai, Jan iankko Lieskovsky, and Zbysek Mraz discovered
that Kerberos did not correctly handle certain GSS packets. An
unauthenticated remote attacker could send specially crafted traffic
that would cause services using GSS-API to crash, leading to a denial
of service. (CVE-2010-0628)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 9.10.");

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

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.7dfsg~beta3-1ubuntu0.5", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.7dfsg~beta3-1ubuntu0.5", rls:"UBUNTU9.10"))) {
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
