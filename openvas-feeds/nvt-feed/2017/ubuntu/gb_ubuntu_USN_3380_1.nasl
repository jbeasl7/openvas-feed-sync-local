# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843272");
  script_cve_id("CVE-2014-0250", "CVE-2014-0791", "CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");
  script_tag(name:"creation_date", value:"2017-08-08 05:19:43 +0000 (Tue, 08 Aug 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-25 15:20:55 +0000 (Fri, 25 May 2018)");

  script_name("Ubuntu: Security Advisory (USN-3380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3380-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3380-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the USN-3380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled certain width and height
values. A malicious server could use this issue to cause FreeRDP to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only applied to Ubuntu 14.04 LTS. (CVE-2014-0250)

It was discovered that FreeRDP incorrectly handled certain values in a
Scope List. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2014-0791)

Tyler Bohan discovered that FreeRDP incorrectly handled certain length
values. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2017-2834, CVE-2017-2835)

Tyler Bohan discovered that FreeRDP incorrectly handled certain packets. A
malicious server could possibly use this issue to cause FreeRDP to crash,
resulting in a denial of service. (CVE-2017-2836, CVE-2017-2837,
CVE-2017-2838, CVE-2017-2839)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp1", ver:"1.0.2-2ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client1.1", ver:"1.1.0~git20140921.1.440916e+dfsg1-10ubuntu1.1", rls:"UBUNTU17.04"))) {
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
