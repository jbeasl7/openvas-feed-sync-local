# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840799");
  script_cve_id("CVE-2011-3601", "CVE-2011-3602", "CVE-2011-3604", "CVE-2011-3605");
  script_tag(name:"creation_date", value:"2011-11-11 04:25:29 +0000 (Fri, 11 Nov 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1257-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1257-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radvd' package(s) announced via the USN-1257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasiliy Kulikov discovered that radvd incorrectly parsed the
ND_OPT_DNSSL_INFORMATION option. A remote attacker could exploit this with
a specially-crafted request and cause the radvd daemon to crash, or
possibly execute arbitrary code. The default compiler options for affected
releases should reduce the vulnerability to a denial of service. This issue
only affected Ubuntu 11.04 and 11.10. (CVE-2011-3601)

Vasiliy Kulikov discovered that radvd incorrectly filtered interface names
when creating certain files. A local attacker could exploit this to
overwrite certain files on the system, bypassing intended permissions.
(CVE-2011-3602)

Vasiliy Kulikov discovered that radvd incorrectly handled certain lengths.
A remote attacker could exploit this to cause the radvd daemon to crash,
resulting in a denial of service. (CVE-2011-3604)

Vasiliy Kulikov discovered that radvd incorrectly handled delays when used
in unicast mode, which is not the default in Ubuntu. If used in unicast
mode, a remote attacker could cause radvd outages, resulting in a denial of
service. (CVE-2011-3605)");

  script_tag(name:"affected", value:"'radvd' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.3-1.1ubuntu0.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.6-1ubuntu0.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.7-1ubuntu0.1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.8-1ubuntu0.1", rls:"UBUNTU11.10"))) {
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
