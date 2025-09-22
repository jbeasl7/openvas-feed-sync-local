# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844600");
  script_cve_id("CVE-2019-16869", "CVE-2019-20444", "CVE-2019-20445");
  script_tag(name:"creation_date", value:"2020-09-23 03:00:22 +0000 (Wed, 23 Sep 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 14:21:03 +0000 (Fri, 31 Jan 2020)");

  script_name("Ubuntu: Security Advisory (USN-4532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4532-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4532-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty-3.9' package(s) announced via the USN-4532-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Netty incorrectly handled certain HTTP headers.
By sending an HTTP header with whitespace before the colon, a remote
attacker could possibly use this issue to perform an HTTP request
smuggling attack. (CVE-2019-16869)

It was discovered that Netty incorrectly handled certain HTTP headers.
By sending an HTTP header that lacks a colon, a remote attacker could
possibly use this issue to perform an HTTP request smuggling attack.
(CVE-2019-20444)

It was discovered that Netty incorrectly handled certain HTTP headers.
By sending a Content-Length header accompanied by a second Content-Length
header, or by a Transfer-Encoding header, a remote attacker could possibly
use this issue to perform an HTTP request smuggling attack.
(CVE-2019-20445)");

  script_tag(name:"affected", value:"'netty-3.9' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-3.9-java", ver:"3.9.9.Final-1+deb9u1build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
