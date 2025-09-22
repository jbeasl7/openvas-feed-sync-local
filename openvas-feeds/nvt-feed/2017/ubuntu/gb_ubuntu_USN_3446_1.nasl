# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843333");
  script_cve_id("CVE-2015-5251", "CVE-2015-5286", "CVE-2016-0757");
  script_tag(name:"creation_date", value:"2017-10-12 08:26:31 +0000 (Thu, 12 Oct 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-15 17:57:39 +0000 (Fri, 15 Apr 2016)");

  script_name("Ubuntu: Security Advisory (USN-3446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3446-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3446-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glance' package(s) announced via the USN-3446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hemanth Makkapati discovered that OpenStack Glance incorrectly handled
access restrictions. A remote authenticated user could use this issue to
change the status of images, contrary to access restrictions.
(CVE-2015-5251)

Mike Fedosin and Alexei Galkin discovered that OpenStack Glance incorrectly
handled the storage quota. A remote authenticated user could use this issue
to consume disk resources, leading to a denial of service. (CVE-2015-5286)

Erno Kuvaja discovered that OpenStack Glance incorrectly handled the
show_multiple_locations option. When show_multiple_locations is enabled,
a remote authenticated user could change an image status and upload new
image data. (CVE-2016-0757)");

  script_tag(name:"affected", value:"'glance' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"glance-common", ver:"1:2014.1.5-0ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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
