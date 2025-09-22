# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6909.1");
  script_cve_id("CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"creation_date", value:"2024-07-24 04:08:24 +0000 (Wed, 24 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:05 +0000 (Tue, 23 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-6909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6909-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6909-1");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/changes-to-be-aware-of-when-moving-from-bind-916-to-918");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-6909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bind incorrectly handled a flood of DNS messages
over TCP. A remote attacker could possibly use this issue to cause Bind to
become unstable, resulting in a denial of service. (CVE-2024-0760)

Toshifumi Sakaguchi discovered that Bind incorrectly handled having a very
large number of RRs existing at the same time. A remote attacker could
possibly use this issue to cause Bind to consume resources, leading to a
denial of service. (CVE-2024-1737)

It was discovered that Bind incorrectly handled a large number of SIG(0)
signed requests. A remote attacker could possibly use this issue to cause
Bind to consume resources, leading to a denial of service. (CVE-2024-1975)

Daniel Stranger discovered that Bind incorrectly handled serving both
stable cache data and authoritative zone content. A remote attacker could
possibly use this issue to cause Bind to crash, resulting in a denial of
service. (CVE-2024-4076)

On Ubuntu 20.04 LTS, Bind has been updated from 9.16 to 9.18. In addition
to security fixes, the updated packages contain bug fixes, new features,
and possibly incompatible changes.

Please see the following for more information:

[link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.18.28-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.18.28-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.18.28-0ubuntu0.24.04.1", rls:"UBUNTU24.04 LTS"))) {
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
