# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0003");
  script_cve_id("CVE-2022-40468", "CVE-2023-49606");
  script_tag(name:"creation_date", value:"2025-01-13 04:13:40 +0000 (Mon, 13 Jan 2025)");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-01 16:15:07 +0000 (Wed, 01 May 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0003");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0003.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33206");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/OM62U7F2OTTTTR4PTM6RV3UAOCUHRC75/");
  script_xref(name:"URL", value:"https://lwn.net/Articles/990818/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7140-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7190-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/05/07/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyproxy' package(s) announced via the MGASA-2025-0003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Potential leak of left-over heap data if custom error page templates
containing special non-standard variables are used. Tinyproxy commit
84f203f and earlier use uninitialized buffers in process_request()
function.. (CVE-2022-40468)
A use-after-free vulnerability exists in the HTTP Connection Headers
parsing in Tinyproxy 1.11.1 and Tinyproxy 1.10.0. A specially crafted
HTTP header can trigger reuse of previously freed memory, which leads to
memory corruption and could lead to remote code execution. An attacker
needs to make an unauthenticated HTTP request to trigger this
vulnerability. (CVE-2023-49606)");

  script_tag(name:"affected", value:"'tinyproxy' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"tinyproxy", rpm:"tinyproxy~1.10.0~3.1.mga9", rls:"MAGEIA9"))) {
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
