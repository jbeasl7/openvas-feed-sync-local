# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7036.1");
  script_cve_id("CVE-2022-30122", "CVE-2022-30123", "CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572", "CVE-2023-27530", "CVE-2023-27539", "CVE-2024-25126", "CVE-2024-26141", "CVE-2024-26146");
  script_tag(name:"creation_date", value:"2024-09-27 04:08:00 +0000 (Fri, 27 Sep 2024)");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-07 04:38:59 +0000 (Wed, 07 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-7036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7036-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7036-1");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/ruby-rack/+bug/2078711");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the USN-7036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Rack was not properly parsing data when processing
multipart POST requests. If a user or automated system were tricked into
sending a specially crafted multipart POST request to an application using
Rack, a remote attacker could possibly use this issue to cause a denial of
service. (CVE-2022-30122)

It was discovered that Rack was not properly escaping untrusted data when
performing logging operations, which could cause shell escaped sequences
to be written to a terminal. If a user or automated system were tricked
into sending a specially crafted request to an application using Rack, a
remote attacker could possibly use this issue to execute arbitrary code in
the machine running the application. (CVE-2022-30123)

It was discovered that Rack did not properly structure regular expressions
in some of its parsing components, which could result in uncontrolled
resource consumption if an application using Rack received specially
crafted input. A remote attacker could possibly use this issue to cause a
denial of service. (CVE-2022-44570, CVE-2022-44571)

It was discovered that Rack did not properly structure regular expressions
in its multipart parsing component, which could result in uncontrolled
resource consumption if an application using Rack to parse multipart posts
received specially crafted input. A remote attacker could possibly use
this issue to cause a denial of service. (CVE-2022-44572)

It was discovered that Rack incorrectly handled Multipart MIME parsing.
A remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. (CVE-2023-27530)

It was discovered that Rack incorrectly handled certain regular
expressions. A remote attacker could possibly use this issue to cause
Rack to consume resources, leading to a denial of service.
(CVE-2023-27539)

It was discovered that Rack incorrectly parsed certain media types. A
remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. (CVE-2024-25126)

It was discovered that Rack incorrectly handled certain Range headers. A
remote attacker could possibly use this issue to cause Rack to create
large responses, leading to a denial of service. (CVE-2024-26141)

It was discovered that Rack incorrectly handled certain crafted headers. A
remote attacker could possibly use this issue to cause Rack to consume
resources, leading to a denial of service. (CVE-2024-26146)");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack", ver:"2.1.4-5ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
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
