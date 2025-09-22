# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7334.1");
  script_cve_id("CVE-2025-1931", "CVE-2025-1932", "CVE-2025-1933", "CVE-2025-1934", "CVE-2025-1935", "CVE-2025-1936", "CVE-2025-1937", "CVE-2025-1942");
  script_tag(name:"creation_date", value:"2025-03-07 04:04:14 +0000 (Fri, 07 Mar 2025)");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7334-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7334-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-7334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information across domains, or execute arbitrary code. (CVE-2025-1933,
CVE-2025-1934, CVE-2025-1935, CVE-2025-1936, CVE-2025-1937, CVE-2025-1942)

It was discovered that Firefox did not properly handle WebTransport
connection, leading to a use-after-free vulnerability. An attacker could
potentially exploit this issue to cause a denial of service.
(CVE-2025-1931)

Ivan Fratric discovered that Firefox did not properly handle XSLT sorting,
leading to a out-of-bounds access vulnerability. An attacker could
potentially exploit this issue to cause a denial of service, or execute
arbitrary code. (CVE-2025-1932)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"136.0+build3-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
