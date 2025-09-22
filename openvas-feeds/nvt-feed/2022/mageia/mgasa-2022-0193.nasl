# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0193");
  script_cve_id("CVE-2022-0005", "CVE-2022-21131", "CVE-2022-21136", "CVE-2022-21151");
  script_tag(name:"creation_date", value:"2022-05-23 04:32:41 +0000 (Mon, 23 May 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-01 17:05:57 +0000 (Wed, 01 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0193");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0193.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30425");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20220510");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00614.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00616.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00617.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2022-0193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated microcodes for Intel processors, fixing various functional
issues, and at least the following security issues:

Sensitive information accessible by physical probing of JTAG interface
for some Intel(R) Processors with SGX may allow an unprivileged user to
potentially enable information disclosure via physical access
(CVE-2022-0005).

Description: Improper access control for some Intel(R) Xeon(R) Processors
may allow an authenticated user to potentially enable information disclosure
via local access (CVE-2022-21131).

Improper input validation for some Intel(R) Xeon(R) Processors may allow a
privileged user to potentially enable denial of service via local access
(CVE-2022-21136).

Processor optimization removal or modification of security-critical code for
some Intel(R) Processors may allow an authenticated user to potentially enable
information disclosure via local access (CVE-2022-21151).

For info about the other fixes in this update, see the github reference.");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20220510~1.mga8.nonfree", rls:"MAGEIA8"))) {
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
