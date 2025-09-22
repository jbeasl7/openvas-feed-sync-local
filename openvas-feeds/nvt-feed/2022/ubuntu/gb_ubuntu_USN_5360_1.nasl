# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845304");
  script_cve_id("CVE-2020-13943", "CVE-2020-17527", "CVE-2020-9484", "CVE-2021-25122", "CVE-2021-25329", "CVE-2021-30640", "CVE-2021-33037", "CVE-2021-41079");
  script_tag(name:"creation_date", value:"2022-04-01 01:00:32 +0000 (Fri, 01 Apr 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-28 18:55:18 +0000 (Tue, 28 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-5360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5360-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5360-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/tomcat9/+bug/1915911");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9' package(s) announced via the USN-5360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly performed input verification.
A remote attacker could possibly use this issue to intercept sensitive
information. (CVE-2020-13943, CVE-2020-17527, CVE-2021-25122, CVE-2021-30640)

It was discovered that Tomcat did not properly deserialize untrusted data.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2020-9484, CVE-2021-33037)

It was discovered that Tomcat did not properly validate the input length. An
attacker could possibly use this to trigger an infinite loop, resulting in a
denial of service. (CVE-2021-25329, CVE-2021-41079)");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.16-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.16-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.16-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.16-3ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.31-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.31-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.31-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.31-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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
