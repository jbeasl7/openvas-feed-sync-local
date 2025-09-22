# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123060");
  script_cve_id("CVE-2015-4142");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:50 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-1439)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1439");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa_supplicant' package(s) announced via the ELSA-2015-1439 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:0.7.3-6]
- AP WMM: Fix integer underflow in WMM Action frame parser (rh #1221178) (rh #1226396)

[1:0.7.3-5]
- Add domain_match config option from upstream (rh #1186806) (rh #1178263)
- Include peer certificate in EAP events for use by clients
- Add dbus signal for information about server certification
- eapol_test: Add option for writing server certificate chain to a file");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.7.3~6.el6", rls:"OracleLinux6"))) {
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
