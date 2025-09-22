# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123094");
  script_cve_id("CVE-2015-3204");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:17 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-1154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1154");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1154.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreswan' package(s) announced via the ELSA-2015-1154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.12-10.1.0.1]
- add libreswan-oracle.patch to detect Oracle Linux distro

[3.12-10.1]
- Resolves: rhbz#1226407 CVE-2015-3204 libreswan: crafted IKE packet causes daemon restart

[3.12-10]
- Resolves: rhbz#1213652 Support CAVS [updated another prf() free symkey, bogus fips mode fix]

[3.12-9]
- Resolves: rhbz#1213652 Support CAVS [updated to kill another copy of prf()]
- Resolves: rhbz#1208023 Libreswan with IPv6 [updated patch by Jaroslav Aster]
- Resolves: rhbz#1208022 libreswan ignores module blacklist [updated modprobe handling]

[3.12-8]
- Resolves: rhbz#1213652 Support CAVS testing of the PRF/PRF+ functions

[3.12-7]
- Resolves: rhbz#1208022 libreswan ignores module blacklist rules
- Resolves: rhbz#1208023 Libreswan with IPv6 in RHEL7 fails after reboot
- Resolves: rhbz#1211146 pluto crashes in fips mode

[3.12-6]
- Resolves: rhbz#1198650 SELinux context string size limit
- Resolves: rhbz#1198649 Add new option for BSI random requirement");

  script_tag(name:"affected", value:"'libreswan' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.12~10.1.0.1.el7_1", rls:"OracleLinux7"))) {
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
