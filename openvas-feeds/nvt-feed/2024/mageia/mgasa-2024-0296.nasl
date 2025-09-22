# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0296");
  script_cve_id("CVE-2023-42667", "CVE-2023-49141", "CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_tag(name:"creation_date", value:"2024-09-12 04:12:48 +0000 (Thu, 12 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0296");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0296.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33511");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20240813");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2024/08/16/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2024-0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper isolation in the Intel(R) Core(TM) Ultra Processor stream cache
mechanism may allow an authenticated user to potentially enable
escalation of privilege via local access. (CVE-2023-42667)
Improper isolation in some Intel(R) Processors stream cache mechanism
may allow an authenticated user to potentially enable escalation of
privilege via local access. (CVE-2023-49141)
Incorrect behavior order in transition between executive monitor and SMI
transfer monitor (STM) in some Intel(R) Processor may allow a privileged
user to potentially enable escalation of privilege via local access.
(CVE-2024-24853)
Protection mechanism failure in some 3rd, 4th, and 5th Generation
Intel(R) Xeon(R) Processors may allow a privileged user to potentially
enable escalation of privilege via local access. (CVE-2024-24980)
Mirrored regions with different values in 3rd Generation Intel(R)
Xeon(R) Scalable Processors may allow a privileged user to potentially
enable denial of service via local access. (CVE-2024-25939)");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20240813~1.mga9.nonfree", rls:"MAGEIA9"))) {
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
