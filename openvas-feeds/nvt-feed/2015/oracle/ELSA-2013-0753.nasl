# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123640");
  script_cve_id("CVE-2013-1926", "CVE-2013-1927");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:39 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0753)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0753");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0753.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web' package(s) announced via the ELSA-2013-0753 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.3-2]
- Added (temporally!) posttrans forcing creation of symlinks
 - should be removed next release
- Resolves: rhbz#949094

[1.2.3-1]
- fixed postun - removal of alternatives for plugin restricted to
 (correct) removal process only
- fixed date in changelog previous entry
- Resolves: rhbz#949094

[1.2.3-0]
- Updated to latest ustream release of 1.2 branch - 1.2.3
 - Security Updates
 - CVE-2013-1927, RH884705 - fixed gifar vulnerability
 - CVE-2013-1926, RH916774: Class-loader incorrectly shared for applets with same relative-path.
 - Common
 - PR1161: X509VariableTrustManager does not work correctly with OpenJDK7
 - Plugin
 - PR1157: Applets can hang browser after fatal exception
- Removed upstreamed patch 0- icedtea-web-PR1161.patch
- Resolves: rhbz#949094");

  script_tag(name:"affected", value:"'icedtea-web' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.2.3~2.el6_4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.2.3~2.el6_4", rls:"OracleLinux6"))) {
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
