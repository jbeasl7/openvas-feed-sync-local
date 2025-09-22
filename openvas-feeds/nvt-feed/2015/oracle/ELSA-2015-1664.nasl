# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123021");
  script_cve_id("CVE-2015-2721", "CVE-2015-2730");
  script_tag(name:"creation_date", value:"2015-10-06 06:46:44 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-1664)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1664");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1664.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the ELSA-2015-1664 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.19.1-1]
- Rebase nss to 3.19.1
- Pick up upstream fix for client auth. regression caused by 3.19.1
- Revert upstream change to minimum key sizes
- Remove patches that rendered obsolete by the rebase
- Update existing patches on account of the rebase

[3.18.0-7]
- Pick up upstream patch from nss-3.19.1
- Resolves: Bug 1236954 - CVE-2015-2730 NSS: ECDSA signature validation fails to handle some signatures correctly (MFSA 2015-64)
- Resolves: Bug 1236967 - CVE-2015-2721 NSS: incorrectly permitted skipping of ServerKeyExchange (MFSA 2015-71)");

  script_tag(name:"affected", value:"'nss' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.19.1~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.19.1~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.19.1~1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.19.1~1.el5_11", rls:"OracleLinux5"))) {
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
