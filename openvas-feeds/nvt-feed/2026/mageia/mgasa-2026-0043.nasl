# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0043");
  script_cve_id("CVE-2024-24853", "CVE-2025-31648");
  script_tag(name:"creation_date", value:"2026-02-19 04:41:03 +0000 (Thu, 19 Feb 2026)");
  script_version("2026-02-19T05:56:52+0000");
  script_tag(name:"last_modification", value:"2026-02-19 05:56:52 +0000 (Thu, 19 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0043");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0043.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35130");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20260210-rev1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2026-0043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package updates AMD CPUs microcodes and fixes security
vulnerabilities in Intel CPUs microcodes:
Incorrect behavior order in transition between executive monitor and SMI
transfer monitor (STM) in some Intel(R) Processor may allow a privileged
user to potentially enable escalation of privilege via local access.
(CVE-2024-24853)
Improper handling of values in the microcode flow for some Intel(R)
Processor Family may allow an escalation of privilege. Startup code and
smm adversary with a privileged user combined with a high complexity
attack may enable escalation of privilege. This result may potentially
occur via local access when attack requirements are present with special
internal knowledge and requires no user interaction. The potential
vulnerability may impact the confidentiality (low), integrity (low) and
availability (none) of the vulnerable system, resulting in subsequent
system confidentiality (low), integrity (low) and availability (none)
impacts. (CVE-2025-31648)");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20260210~1.mga9.nonfree", rls:"MAGEIA9"))) {
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
