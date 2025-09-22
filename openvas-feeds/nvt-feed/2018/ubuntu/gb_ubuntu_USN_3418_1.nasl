# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843752");
  script_cve_id("CVE-2017-2862", "CVE-2017-2870", "CVE-2017-6311");
  script_tag(name:"creation_date", value:"2018-10-26 04:15:13 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 20:40:25 +0000 (Fri, 08 Sep 2017)");

  script_name("Ubuntu: Security Advisory (USN-3418-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3418-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3418-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the USN-3418-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GDK-PixBuf library did not properly handle
certain jpeg images. If an user or automated system were tricked into
opening a specially crafted jpeg file, a remote attacker could use this
flaw to cause GDK-PixBuf to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2017-2862)

It was discovered that the GDK-PixBuf library did not properly handle
certain tiff images. If an user or automated system were tricked into
opening a specially crafted tiff file, a remote attacker could use this
flaw to cause GDK-PixBuf to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2017-2870)

Ariel Zelivansky discovered that the GDK-PixBuf library did not properly
handle printing certain error messages. If an user or automated system were
tricked into opening a specially crafted image file, a remote attacker
could use this flaw to cause GDK-PixBuf to crash, resulting in a denial of
service. (CVE-2017-6311)");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.30.7-0ubuntu1.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.32.2-1ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libgdk-pixbuf2.0-0", ver:"2.36.5-3ubuntu0.2", rls:"UBUNTU17.04"))) {
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
