# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841938");
  script_cve_id("CVE-2014-3476", "CVE-2014-3520", "CVE-2014-5251", "CVE-2014-5252", "CVE-2014-5253");
  script_tag(name:"creation_date", value:"2014-08-22 03:57:19 +0000 (Fri, 22 Aug 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2324-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2324-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2324-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keystone' package(s) announced via the USN-2324-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steven Hardy discovered that OpenStack Keystone did not properly handle
chained delegation. A remove authenticated attacker could use this to
gain privileges by creating a new token with additional roles.
(CVE-2014-3476)

Jamie Lennox discovered that OpenStack Keystone did not properly validate
the project id. A remote authenticated attacker may be able to use this to
access other projects. (CVE-2014-3520)

Brant Knudson and Lance Bragstad discovered that OpenStack Keystone would
not always revoke tokens correctly. If Keystone were configured to use
revocation events, a remote authenticated attacker could continue to have
access to resources. (CVE-2014-5251, CVE-2014-5252, CVE-2014-5253)");

  script_tag(name:"affected", value:"'keystone' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-keystone", ver:"1:2014.1.2.1-0ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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
