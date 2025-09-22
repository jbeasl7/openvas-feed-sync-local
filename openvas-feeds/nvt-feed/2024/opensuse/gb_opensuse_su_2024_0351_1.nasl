# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856704");
  script_cve_id("CVE-2024-21272");
  script_tag(name:"creation_date", value:"2024-11-08 05:00:42 +0000 (Fri, 08 Nov 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:18 +0000 (Tue, 15 Oct 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A4QYWY7IAP4RFAA3R6QMK3Q6FFAY4UOZ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231740");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-mysql-connector-python' package(s) announced via the openSUSE-SU-2024:0351-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-mysql-connector-python fixes the following issues:

- Update to 9.1.0 (boo#1231740, CVE-2024-21272)
 - WL#16452: Bundle all installable authentication plugins when building the C-extension
 - WL#16444: Drop build support for DEB packages
 - WL#16442: Upgrade gssapi version to 1.8.3
 - WL#16411: Improve wheel metadata information for Classic and XDevAPI connectors
 - WL#16341: OpenID Connect (Oauth2 - JWT) Authentication Support
 - WL#16307: Remove Python 3.8 support
 - WL#16306: Add support for Python 3.13
 - BUG#37055435: Connection fails during the TLS negotiation when specifying TLSv1.3 ciphers
 - BUG#37013057: mysql-connector-python Parameterized query SQL injection
 - BUG#36765200: python mysql connector 8.3.0 raise %-.100s:%u when input a wrong host
 - BUG#36577957: Update charset/collation description indicate this is 16 bits
- 9.0.0:
 - WL#16350: Update dnspython version
 - WL#16318: Deprecate Cursors Prepared Raw and Named Tuple
 - WL#16284: Update the Python Protobuf version
 - WL#16283: Remove OpenTelemetry Bundled Installation
 - BUG#36664998: Packets out of order error is raised while changing user in aio
 - BUG#36611371: Update dnspython required versions to allow latest 2.6.1
 - BUG#36570707: Collation set on connect using C-Extension is ignored
 - BUG#36476195: Incorrect escaping in pure Python mode if sql_mode includes NO_BACKSLASH_ESCAPES
 - BUG#36289767: MySQLCursorBufferedRaw does not skip conversion
- 8.4.0
 - WL#16203: GPL License Exception Update
 - WL#16173: Update allowed cipher and cipher-suite lists
 - WL#16164: Implement support for new vector data type
 - WL#16127: Remove the FIDO authentication mechanism
 - WL#16053: Support GSSAPI/Kerberos authentication on Windows using authentication_ldap_sasl_client plug-in for C-extension
 - BUG#36227964: Improve OpenTelemetry span coverage
 - BUG#36167880: Massive memory leak mysqlx native Protobuf adding to collection
- 8.3.0
 - WL#16015: Remove use of removed COM_ commands
 - WL#15985: Support GSSAPI/Kerberos authentication on Windows using authentication_ldap_sasl_client plug-in for Pure Python
 - WL#15983: Stop using mysql_ssl_set api
 - WL#15982: Remove use of mysql_shutdown
 - WL#15950: Support query parameters for prepared statements
 - WL#15942: Improve type hints and standardize byte type handling
 - WL#15836: Split mysql and mysqlx into different packages
 - WL#15523: Support Python DB API asynchronous execution
 - BUG#35912790: Binary strings are converted when using prepared statements
 - BUG#35832148: Fix Django timezone.utc deprecation warning
 - BUG#35710145: Bad MySQLCursor.statement and result when query text contains code comments
 - BUG#21390859: STATEMENTS GET OUT OF SYNCH WITH RESULT SETS");

  script_tag(name:"affected", value:"'python-mysql-connector-python' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python3-mysql-connector-python", rpm:"python3-mysql-connector-python~9.1.0~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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
