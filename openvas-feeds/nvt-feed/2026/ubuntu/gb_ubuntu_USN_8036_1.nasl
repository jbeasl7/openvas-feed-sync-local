# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8036.1");
  script_cve_id("CVE-2026-26081");
  script_tag(name:"creation_date", value:"2026-02-16 04:42:51 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-16T06:02:08+0000");
  script_tag(name:"last_modification", value:"2026-02-16 06:02:08 +0000 (Mon, 16 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-8036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU25\.10");

  script_xref(name:"Advisory-ID", value:"USN-8036-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8036-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy' package(s) announced via the USN-8036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asim Viladi Oglu Manizada discovered that HAProxy incorrectly handled
certain INITIAL packets. A remote attacker could possibly use this issue
to cause HAProxy to crash, resulting in a denial of service.");

  script_tag(name:"affected", value:"'haproxy' package(s) on Ubuntu 25.10.");

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

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"haproxy", ver:"3.0.12-0ubuntu0.25.10.3", rls:"UBUNTU25.10"))) {
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
