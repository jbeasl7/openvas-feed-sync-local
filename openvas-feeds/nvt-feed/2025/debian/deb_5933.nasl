# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.5933");
  script_cve_id("CVE-2024-22640", "CVE-2024-22641", "CVE-2024-32489", "CVE-2024-51058", "CVE-2024-56519", "CVE-2024-56520", "CVE-2024-56522", "CVE-2024-56527");
  script_tag(name:"creation_date", value:"2025-06-02 04:11:51 +0000 (Mon, 02 Jun 2025)");
  script_version("2025-06-02T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5933-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5933-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-5933-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tcpdf' package(s) announced via the DSA-5933-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'tcpdf' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"php-tcpdf", ver:"6.6.2+dfsg1-1+deb12u1", rls:"DEB12"))) {
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
