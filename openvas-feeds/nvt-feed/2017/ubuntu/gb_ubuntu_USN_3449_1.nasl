# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843332");
  script_cve_id("CVE-2015-3241", "CVE-2015-3280", "CVE-2015-5162", "CVE-2015-7548", "CVE-2015-7713", "CVE-2015-8749", "CVE-2016-2140");
  script_tag(name:"creation_date", value:"2017-10-12 08:26:14 +0000 (Thu, 12 Oct 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-07 17:12:48 +0000 (Fri, 07 Oct 2016)");

  script_name("Ubuntu: Security Advisory (USN-3449-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3449-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3449-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-3449-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"George Shuklin discovered that OpenStack Nova incorrectly handled the
migration process. A remote authenticated user could use this issue to
consume resources, resulting in a denial of service. (CVE-2015-3241)

George Shuklin and Tushar Patil discovered that OpenStack Nova incorrectly
handled deleting instances. A remote authenticated user could use this
issue to consume disk resources, resulting in a denial of service.
(CVE-2015-3280)

It was discovered that OpenStack Nova incorrectly limited qemu-img calls. A
remote authenticated user could use this issue to consume resources,
resulting in a denial of service. (CVE-2015-5162)

Matthew Booth discovered that OpenStack Nova incorrectly handled snapshots.
A remote authenticated user could use this issue to read arbitrary files.
(CVE-2015-7548)

Sreekumar S. and Suntao discovered that OpenStack Nova incorrectly applied
security group changes. A remote attacker could possibly use this issue to
bypass intended restriction changes by leveraging an instance that was
running when the change was made. (CVE-2015-7713)

Matt Riedemann discovered that OpenStack Nova incorrectly handled logging.
A local attacker could possibly use this issue to obtain sensitive
information from log files. (CVE-2015-8749)

Matthew Booth discovered that OpenStack Nova incorrectly handled certain
qcow2 headers. A remote authenticated user could possibly use this issue to
read arbitrary files. (CVE-2016-2140)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"1:2014.1.5-0ubuntu1.7", rls:"UBUNTU14.04 LTS"))) {
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
