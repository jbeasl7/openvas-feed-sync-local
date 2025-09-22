# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122485");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188", "CVE-2009-3604", "CVE-2009-3606");
  script_tag(name:"creation_date", value:"2015-10-08 11:46:26 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-0480)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-0480");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-0480.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the ELSA-2009-0480 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.5.4-4.4.el5_3.9]
- Another fix of integer overflows.
- Adds memory-allocation.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.8]
- Change calling of exit() to _exit().
- Adds exit-handling.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.7]
- Improve handling of EOF at JBIG2Stream.cc.
- Adds eof-handling.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.6]
- Memory handling from upstream.
- Removes CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.allocation-size-check.patch.
- Adds upstream-memory-handling.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.5]
- Fix allocation of memory in several functions.
- Adds CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.allocation-size-check.patch.
- Removes CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.long-int.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.4]
- Fix allocation of memory in several functions.
- Add CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.long-type.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.3]
- Add CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.mem.patch.
- Resolves: #490707

[0.5.4-4.4.el5_3.2]
- A little change of spec file because to pass *RPM requires/provides* test.
- Resolves: #490707

[0.5.4-4.4.el5_3.1]
- Add CVE-2009-0146.CVE-2009-0147.CVE-2009-0166.patch.
- Resolves: #490707");

  script_tag(name:"affected", value:"'poppler' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~4.4.el5_3.9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~4.4.el5_3.9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.5.4~4.4.el5_3.9", rls:"OracleLinux5"))) {
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
