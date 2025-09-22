# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123150");
  script_cve_id("CVE-2015-0283", "CVE-2015-1827");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-0728)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0728");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0728.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa, slapi-nis' package(s) announced via the ELSA-2015-0728 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ipa
[4.1.0-18.0.1.el7_1.3]
- Replace login-screen-logo.png [20362818]
- Drop subscription-manager requires for OL7
- Drop redhat-access-plugin-ipa requires for OL7
- Blank out header-logo.png product-name.png

[4.1.0-18.3]
- [ipa-python] ipalib.errors.LDAPError: failed to decode certificate:
 (SEC_ERROR_INVALID_ARGS) security library: invalid arguments. (#1194312)

[4.1.0-18.2]
- IPA extdom plugin fails when encountering large groups (#1193759)
- CVE-2015-0283 ipa: slapi-nis: infinite loop in getgrnam_r() and getgrgid_r()
 (#1202997)

[4.1.0-18.1]
- 'an internal error has occurred' during ipa host-del --updatedns (#1198431)
- Renamed patch 1013 to 0114, as it was merged upstream
- Fax number not displayed for user-show when kinit'ed as normal user.
 (#1198430)
- Replication agreement with replica not disabled when ipa-restore done without
 IPA installed (#1199060)
- Limit deadlocks between DS plugin DNA and slapi-nis (#1199128)

slapi-nis
[0.54-3]
- Fix CVE-2015-0283
- Resolves: #1202995");

  script_tag(name:"affected", value:"'ipa, slapi-nis' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slapi-nis", rpm:"slapi-nis~0.54~3.el7_1", rls:"OracleLinux7"))) {
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
