# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122740");
  script_cve_id("CVE-2014-8602");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:17 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2455");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2455.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound' package(s) announced via the ELSA-2015-2455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.4.20-26]
- Added Conflicts on redhat-release packages without unbound-anchor.timer in presets (Related #1215645)

[1.4.20-25]
- Resolve ordering loop with nss-lookup.target and ntpdate (#1259806)

[1.4.20-24]
- Fix CVE-2014-8602 (#1253961)

[1.4.20-23]
- Removed usage of DLV from the default configuration (#1223339)

[1.4.20-22]
- unbound.service now Wants unbound-anchor.timer (Related: #1180267)

[1.4.20-21]
- Fix dependencies and minor scriptlet issues due to systemd timer unit (Related: #1180267)

[1.4.20-20]
- Install tmpfiles configuration into /usr/lib/tmpfiles.d (#1180995)
- Fix root key management to comply to RFC5011 (#1180267)");

  script_tag(name:"affected", value:"'unbound' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.4.20~26.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.4.20~26.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.4.20~26.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-python", rpm:"unbound-python~1.4.20~26.el7", rls:"OracleLinux7"))) {
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
