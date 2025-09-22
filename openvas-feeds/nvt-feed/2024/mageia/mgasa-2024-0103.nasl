# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0103");
  script_cve_id("CVE-2023-22655", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-43490");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0103");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0103.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33015");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20240312");
  script_xref(name:"URL", value:"https://lwn.net/Articles/966603/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2024-0103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Protection mechanism failure in some 3rd and 4th Generation Intel(R)
Xeon(R) Processors when using Intel(R) SGX or Intel(R) TDX may allow a
privileged user to potentially enable escalation of privilege via local
access. (CVE-2023-22655)
Information exposure through microarchitectural state after transient
execution from some register files for some Intel(R) Atom(R) Processors
may allow an authenticated user to potentially enable information
disclosure via local access. (CVE-2023-28746)
Non-transparent sharing of return predictor targets between contexts in
some Intel(R) Processors may allow an authorized user to potentially
enable information disclosure via local access. (CVE-2023-38575)
Protection mechanism failure of bus lock regulator for some Intel(R)
Processors may allow an unauthenticated user to potentially enable
denial of service via network access. (CVE-2023-39368)
Incorrect calculation in microcode keying mechanism for some Intel(R)
Xeon(R) D Processors with Intel(R) SGX may allow a privileged user to
potentially enable information disclosure via local access.
(CVE-2023-43490)");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20240312~1.mga9.nonfree", rls:"MAGEIA9"))) {
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
