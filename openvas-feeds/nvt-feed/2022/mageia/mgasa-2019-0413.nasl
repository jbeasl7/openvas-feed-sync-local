# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0413");
  script_cve_id("CVE-2018-12207", "CVE-2019-0117", "CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-20 18:02:32 +0000 (Wed, 20 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0413)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0413");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0413.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25686");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25896");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/blob/master/releasenote");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00164.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00210.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00270.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00271.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/support/articles/000055650/processors/intel-xeon-processors.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2019-0413 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NOTE! This is a refresh of the 20191112 security update we released
as MGASA-2019-0334.
This update provides the Intel 20191115 microcode release that adds
more microcode side fixes and mitigations for the Core Gen 6 to Core
gen 10, some Xeon E series, addressing at least the following security
issues:

A flaw was found in the implementation of SGX around the access control
of protected memory. A local attacker of a system with SGX enabled and
an affected intel GPU with the ability to execute code is able to infer
the contents of the SGX protected memory (CVE-2019-0117).

TSX Asynchronous Abort condition on some CPUs utilizing speculative
execution may allow an authenticated user to potentially enable information
disclosure via a side channel with local access. (CVE-2019-11135).

Improper conditions check in the voltage modulation interface for some
Intel(R) Xeon(R) Scalable Processors may allow a privileged user to
potentially enable denial of service via local access (CVE-2019-11139).

Improper invalidation for page table updates by a virtual guest operating
system for multiple Intel(R) Processors may allow an authenticated user to
potentially enable denial of service of the host system via local access
(CVE-2018-12207).

TA Indirect Sharing Erratum (Information Leak)

Incomplete fixes for previous MDS mitigations (VERW)

SHUF* instruction implementation flaw (DoS)

EGETKEY Erratum

Conditional Jump Macro-fusion (DoS or Privilege Escalation)

For the software side fixes and mitigations of these issues, the kernel
must be updated to 5.3.13-1.mga7 (mga$?25686) or later.");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20191115~1.mga7.nonfree", rls:"MAGEIA7"))) {
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
