# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122374");
  script_cve_id("CVE-2009-2855", "CVE-2010-0308");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0221");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the ELSA-2010-0221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7:2.6.STABLE21-6]
- Resolves: #561828 - CVE-2009-2855 CVE-2010-0308 squid various flaws [rhel-5.5]

[7:2.6.STABLE21-5]
- Resolves: #538738 - improved patch

[7:2.6.STABLE21-4]
- Resolves: #521926 - squid 'stop after stop' is not LSB compliant
- Resolves: #496170 - Add arp filter option
- Resolves: #516245 - negotiate support not enabled in squid
- Resolves: #538738 - Squid accelerator mode works only if port 80 is opened
- Resolves: #470843 - Squid 'error_map' does not work when used 'Accep-Encoding: gzip'");

  script_tag(name:"affected", value:"'squid' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~2.6.STABLE21~6.el5", rls:"OracleLinux5"))) {
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
