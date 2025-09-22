# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841235");
  script_cve_id("CVE-2010-2810", "CVE-2012-5821");
  script_tag(name:"creation_date", value:"2012-12-04 04:18:39 +0000 (Tue, 04 Dec 2012)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 03:18:43 +0000 (Fri, 09 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-1642-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1642-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1642-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lynx-cur' package(s) announced via the USN-1642-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered a heap-based buffer overflow in Lynx. If a user
were tricked into opening a specially crafted page, a remote attacker could
cause a denial of service via application crash, or possibly execute
arbitrary code as the user invoking the program. This issue only affected
Ubuntu 10.04 LTS. (CVE-2010-2810)

It was discovered that Lynx did not properly verify that an HTTPS
certificate was signed by a trusted certificate authority. This could allow
an attacker to perform a 'machine-in-the-middle' (MITM) attack which would make
the user believe their connection is secure, but is actually being
monitored. This update changes the behavior of Lynx such that self-signed
certificates no longer validate. Users requiring the previous behavior can
use the 'FORCE_SSL_PROMPT' option in lynx.cfg. (CVE-2012-5821)");

  script_tag(name:"affected", value:"'lynx-cur' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"lynx-cur", ver:"2.8.8dev.2-1ubuntu0.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"lynx-cur", ver:"2.8.8dev.9-2ubuntu0.11.10.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"lynx-cur", ver:"2.8.8dev.9-2ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"lynx-cur", ver:"2.8.8dev.12-2ubuntu0.1", rls:"UBUNTU12.10"))) {
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
