# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123540");
  script_cve_id("CVE-2013-4282");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1474)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1474");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1474.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qspice' package(s) announced via the ELSA-2013-1474 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.3.0-56.1]
- Fix spice-server crash when client sends a password which is too long
 Resolves: CVE-2013-4282

[0.3.0-56.el5]
- Fix unsafe accesses
 + spice: drop libpng from windows components (537849)
 + libspice: fix unsafe guest data accessing
Resolves: #568720
 + fix unsafe free() call.
Resolves: #568724
 + spice server: fix unsafe cursor items handling.
Resolves: #568720

[0.3.0-55.el5]
- spice: clear client palette caches on migration
Resolves: #599496");

  script_tag(name:"affected", value:"'qspice' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"qspice", rpm:"qspice~0.3.0~56.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qspice-libs", rpm:"qspice-libs~0.3.0~56.el5_10.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qspice-libs-devel", rpm:"qspice-libs-devel~0.3.0~56.el5_10.1", rls:"OracleLinux5"))) {
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
