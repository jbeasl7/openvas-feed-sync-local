# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122443");
  script_cve_id("CVE-2009-2697");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:29 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2009-1364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1364");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1364.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm' package(s) announced via the ELSA-2009-1364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:2.16.0-56]
- Resolves: #239818 181302
- Fix tcp wrappers detection on 64-bit

[1:2.16.0-55]
Resolves: #196054
- Fix docs subpackage Requires

[1:2.16.0-53]
Resolves: #196054
- Add docs subpackage

[1:2.16.0-52]
Resolves: #226931
- Add te_IN translations

[1:2.16.0-51]
Resolves: #441971
- Make ctrl-alt-backspace at the login screen more robust

[1:2.16.0-50]
Resolves: #458331
- Add GDM to audio group by default.

[1:2.16.0-49]
Resolves: #474588
- Don't crash if defined extended input device is unplugged
 Patch by Olivier Fourdan.

[1:2.16.0-48]
Resolves: #239818
- Rebuild with tcp_wrappers build requires

[1:2.16.0-47]
Resolves: #473262
- Fix pointer on tablet devices.");

  script_tag(name:"affected", value:"'gdm' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.16.0~56.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdm-docs", rpm:"gdm-docs~2.16.0~56.el5", rls:"OracleLinux5"))) {
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
