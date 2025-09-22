# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122540");
  script_cve_id("CVE-2008-4313", "CVE-2008-4315");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:35 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2008-1001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-1001");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-1001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tog-pegasus' package(s) announced via the ELSA-2008-1001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.7.0-2.0.1.el5_2.1]
- Added pegasus-enterprise.patch to allow detection of enterprise-release

[2.7.0-2.el5_2.1]
- Fix local-or-remote-auth patch and enhance PAM security settings
 Resolves: #471370");

  script_tag(name:"affected", value:"'tog-pegasus' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.7.0~2.0.1.el5_2.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.7.0~2.0.1.el5_2.1", rls:"OracleLinux5"))) {
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
