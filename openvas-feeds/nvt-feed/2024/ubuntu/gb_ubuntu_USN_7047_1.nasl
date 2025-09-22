# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7047.1");
  script_cve_id("CVE-2019-10190", "CVE-2019-10191", "CVE-2019-19331", "CVE-2020-12667");
  script_tag(name:"creation_date", value:"2024-10-02 04:07:35 +0000 (Wed, 02 Oct 2024)");
  script_version("2024-10-03T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-10-03 05:05:33 +0000 (Thu, 03 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-21 14:41:07 +0000 (Thu, 21 May 2020)");

  script_name("Ubuntu: Security Advisory (USN-7047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7047-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7047-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'knot-resolver' package(s) announced via the USN-7047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vladimir Cunat discovered that Knot Resolver incorrectly handled input
during DNSSEC validation. A remote attacker could possibly use this issue
to bypass certain validations. (CVE-2019-10190)

Vladimir Cunat discovered that Knot Resolver incorrectly handled input
during DNSSEC validation. A remote attacker could possibly use this issue
to downgrade DNSSEC-secure domains to a DNSSEC-insecure state, resulting
in a domain hijacking attack. (CVE-2019-10191)

Vladimir Cunat discovered that Knot Resolver incorrectly handled certain
DNS replies with many resource records. An attacker could possibly use
this issue to consume system resources, resulting in a denial of service.
(CVE-2019-19331)

Lior Shafir, Yehuda Afek, and Anat Bremler-Barr discovered that Knot
Resolver incorrectly handled certain queries. A remote attacker could
use this issue to perform an amplification attack directed at a target.
(CVE-2020-12667)");

  script_tag(name:"affected", value:"'knot-resolver' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"knot-resolver", ver:"3.2.1-3ubuntu2.2", rls:"UBUNTU20.04 LTS"))) {
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
