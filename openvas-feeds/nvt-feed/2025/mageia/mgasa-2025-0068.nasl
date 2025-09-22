# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0068");
  script_cve_id("CVE-2023-43758", "CVE-2024-31068", "CVE-2024-36293", "CVE-2024-37020", "CVE-2024-39355");
  script_tag(name:"creation_date", value:"2025-02-18 04:07:29 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-18T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-02-18 05:38:27 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0068");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0068.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34020");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20250211");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2025-0068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper Finite State Machines (FSMs) in Hardware Logic for some Intel(r)
Processors may allow privileged user to potentially enable denial of
service via local access. (CVE-2024-31068)
Improper access control in the EDECCSSA user leaf function for some
Intel(r) Processors with Intel(r) SGX may allow an authenticated user to
potentially enable denial of service via local access. (CVE-2024-36293)
Improper input validation in UEFI firmware for some Intel(r) processors
may allow a privileged user to potentially enable escalation of
privilege via local access. (CVE-2023-43758)
Improper handling of physical or environmental conditions in some Intel(r)
Processors may allow an authenticated user to enable denial of service
via local access. (CVE-2024-39355)
Sequence of processor instructions leads to unexpected behavior in the
Intel(r) DSA V1.0 for some Intel(r) Xeon(r) Processors may allow an
authenticated user to potentially enable denial of service via local
access. (CVE-2024-37020)");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20250211~1.mga9.nonfree", rls:"MAGEIA9"))) {
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
