# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844621");
  script_cve_id("CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20024");
  script_tag(name:"creation_date", value:"2020-09-29 03:01:27 +0000 (Tue, 29 Sep 2020)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-07 21:11:03 +0000 (Mon, 07 Jan 2019)");

  script_name("Ubuntu: Security Advisory (USN-4547-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4547-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4547-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ssvnc' package(s) announced via the USN-4547-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the LibVNCClient vendored in SSVNC incorrectly handled
certain packet lengths. A remote attacker could possibly use this issue to
obtain sensitive information, cause a denial of service, or execute arbitrary
code. (CVE-2018-20020, CVE-2018-20021, CVE-2018-20022, CVE-2018-2024)");

  script_tag(name:"affected", value:"'ssvnc' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ssvnc", ver:"1.0.29-2+deb8u1build0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
