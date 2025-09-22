# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841816");
  script_cve_id("CVE-2014-0162");
  script_tag(name:"creation_date", value:"2014-05-12 03:43:30 +0000 (Mon, 12 May 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2193-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU13\.10");

  script_xref(name:"Advisory-ID", value:"USN-2193-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2193-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glance' package(s) announced via the USN-2193-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul McMillan discovered that the Sheepdog backend in OpenStack Glance did
not properly handle untrusted input. A remote authenticated attacker
exploit this to execute arbitrary commands as the glance user.");

  script_tag(name:"affected", value:"'glance' package(s) on Ubuntu 13.10.");

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

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-glance", ver:"1:2013.2.3-0ubuntu1.1", rls:"UBUNTU13.10"))) {
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
