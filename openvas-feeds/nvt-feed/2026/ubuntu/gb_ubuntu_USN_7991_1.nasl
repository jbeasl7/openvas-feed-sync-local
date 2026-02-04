# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7991.1");
  script_cve_id("CVE-2024-10460", "CVE-2024-10461", "CVE-2024-10462", "CVE-2024-10464", "CVE-2024-10465", "CVE-2024-10466", "CVE-2024-10467", "CVE-2024-10468", "CVE-2024-50336", "CVE-2024-9396", "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400", "CVE-2024-9402", "CVE-2024-9403", "CVE-2025-0237", "CVE-2025-0239", "CVE-2025-0240", "CVE-2025-0241", "CVE-2025-0243", "CVE-2025-0247", "CVE-2025-1018", "CVE-2025-1019", "CVE-2025-1020", "CVE-2025-10527", "CVE-2025-10528", "CVE-2025-10529", "CVE-2025-10532", "CVE-2025-10533", "CVE-2025-10536", "CVE-2025-10537", "CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11713", "CVE-2025-11714", "CVE-2025-11715", "CVE-2025-13012", "CVE-2025-13013", "CVE-2025-13014", "CVE-2025-13015", "CVE-2025-13016", "CVE-2025-13017", "CVE-2025-13018", "CVE-2025-13019", "CVE-2025-13020", "CVE-2025-14321", "CVE-2025-14322", "CVE-2025-14323", "CVE-2025-14324", "CVE-2025-14325", "CVE-2025-14327", "CVE-2025-14328", "CVE-2025-14329", "CVE-2025-14330", "CVE-2025-14331", "CVE-2025-1942", "CVE-2025-1943", "CVE-2025-3031", "CVE-2025-3032", "CVE-2025-3034", "CVE-2025-4085", "CVE-2025-4088", "CVE-2025-4089", "CVE-2025-4092", "CVE-2025-5270", "CVE-2025-5271", "CVE-2025-5272", "CVE-2025-5283", "CVE-2025-6427", "CVE-2025-6432", "CVE-2025-6433", "CVE-2025-6434", "CVE-2025-6435", "CVE-2025-6436", "CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-8036", "CVE-2025-8037", "CVE-2025-8038", "CVE-2025-8039", "CVE-2025-8040", "CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181", "CVE-2025-9182", "CVE-2025-9184", "CVE-2025-9185", "CVE-2026-0818", "CVE-2026-0877", "CVE-2026-0878", "CVE-2026-0879", "CVE-2026-0880", "CVE-2026-0882", "CVE-2026-0883", "CVE-2026-0884", "CVE-2026-0885", "CVE-2026-0886", "CVE-2026-0887", "CVE-2026-0890", "CVE-2026-0891");
  script_tag(name:"creation_date", value:"2026-02-03 04:35:20 +0000 (Tue, 03 Feb 2026)");
  script_version("2026-02-03T05:55:35+0000");
  script_tag(name:"last_modification", value:"2026-02-03 05:55:35 +0000 (Tue, 03 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:22:53 +0000 (Wed, 10 Dec 2025)");

  script_name("Ubuntu: Security Advisory (USN-7991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7991-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7991-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-7991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass security restrictions, cross-site
tracing, or execute arbitrary code.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:140.7.1+build1-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
