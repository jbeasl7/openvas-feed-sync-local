# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8022.2");
  script_cve_id("CVE-2026-24515", "CVE-2026-25210");
  script_tag(name:"creation_date", value:"2026-02-17 04:37:15 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-17T05:57:49+0000");
  script_tag(name:"last_modification", value:"2026-02-17 05:57:49 +0000 (Tue, 17 Feb 2026)");
  script_tag(name:"cvss_base", value:"1.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-05 17:27:53 +0000 (Thu, 05 Feb 2026)");

  script_name("Ubuntu: Security Advisory (USN-8022-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-8022-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8022-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the USN-8022-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8022-1 fixed vulnerabilities in Expat. This update provides the
corresponding updates for Ubuntu 24.04 LTS.

Original advisory details:

 It was discovered that Expat incorrectly handled the initialization of parsers
 for external entities. An attacker could possibly use this issue to cause a
 denial of service. (CVE-2026-24515)

 It was discovered that Expat incorrectly handled integer calculations when
 allocating memory for XML tags. An attacker could possibly use this issue to
 cause a denial of service or execute arbitrary code. (CVE-2026-25210)");

  script_tag(name:"affected", value:"'expat' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"expat", ver:"2.6.1-2ubuntu0.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libexpat1", ver:"2.6.1-2ubuntu0.4", rls:"UBUNTU24.04 LTS"))) {
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
