# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122750");
  script_cve_id("CVE-2013-0334");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:25 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2180");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2180.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-bundler, rubygem-thor' package(s) announced via the ELSA-2015-2180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"rubygem-bundler
[1.7.8-3]
- Enforce higher Thor version, which is required by Bundler.
 Related: rhbz#1194243

[1.7.8-2]
- Update to Bundler 1.7.8.
 Resolves: rhbz#1194243
- Use symlinks for vendored libraries.
 Resolves: rhbz#1163076

[1.3.1-3]
- Mass rebuild 2013-12-27

[1.3.1-2]
- Always include Patch100 in SRPM.

[1.3.1-1]
rubygem-thor
[0.19.1-1]
- Update to thor 1.19.1.
 Resolves: rhbz#1209921");

  script_tag(name:"affected", value:"'rubygem-bundler, rubygem-thor' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bundler", rpm:"rubygem-bundler~1.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bundler-doc", rpm:"rubygem-bundler-doc~1.7.8~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-thor", rpm:"rubygem-thor~0.19.1~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-thor-doc", rpm:"rubygem-thor-doc~0.19.1~1.el7", rls:"OracleLinux7"))) {
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
