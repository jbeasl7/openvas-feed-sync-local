# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833764");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2020-15598", "CVE-2021-42717", "CVE-2023-28882", "CVE-2023-38285");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-02 00:39:37 +0000 (Wed, 02 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:47:15 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for modsecurity (openSUSE-SU-2023:0257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0257-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LIQVEGVX3JPH6JWIVOQVDUI4WMZNSIG4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'modsecurity'
  package(s) announced via the openSUSE-SU-2023:0257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for modsecurity fixes the following issues:

     Update to version 3.0.10:


  - Fix: worst-case time in implementation of four transformations

  - Additional information on this issue is available at

  * Enhancements and bug fixes

  - Add TX synonym for MSC_PCRE_LIMITS_EXCEEDED

  - Make MULTIPART_PART_HEADERS accessible to lua

  - Fix: Lua scripts cannot read whole collection at once

  - Fix: quoted Include config with wildcard

  - Support isolated PCRE match limits

  - Fix: meta actions not applied if multiMatch in first rule of chain

  - Fix: audit log may omit tags when multiMatch

  - Exclude CRLF from MULTIPART_PART_HEADER value

  - Configure: use AS_ECHO_N instead echo -n

  - Adjust position of memset from 2890

     Update to version 3.0.9:

  * Add some member variable inits in Transaction class (possible segfault)

  * Fix: possible segfault on reload if duplicate ip+CIDR in ip match list

  * Resolve memory leak on reload (bison-generated variable)

  * Support equals sign in XPath expressions

  * Encode two special chars in error.log output

  * Add JIT support for PCRE2

  * Support comments in ipMatchFromFile file via '#' token

  * Use name package name libmaxminddb with pkg-config

  * Fix: FILES_TMP_CONTENT collection key should use part name

  * Use AS_HELP_STRING instead of obsolete AC_HELP_STRING macro

  * During configure, do not check for pcre if pcre2 specified

  * Use pkg-config to find libxml2 first

  * Fix two rule-reload memory leak issues

  * Correct whitespace handling for Include directive

  - Fix CVE-2023-28882, a segfault and a resultant crash of a worker process
       in some configurations with certain inputs, boo#1210993

     Update to version 3.0.8

  * Adjust parser activation rules in modsecurity.conf-recommended [#2796]

  * Multipart parsing fixes and new MULTIPART_PART_HEADERS collection [#2795]

  * Prevent LMDB related segfault [#2755, #2761]

  * Fix msc_transaction_cleanup function comment typo [#2788]

  * Fix: MULTIPART_INVALID_PART connected to wrong internal variable [#2785]

  * Restore Unique_id to include random portion after timestamp [#2752,
       #2758]

     Update to version 3.0.7

  * Support PCRE2

  * Support SecRequestBodyNoFilesLimit
  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'modsecurity' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3", rpm:"libmodsecurity3~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"modsecurity", rpm:"modsecurity~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"modsecurity-devel", rpm:"modsecurity-devel~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3-64bit", rpm:"libmodsecurity3-64bit~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3-32bit", rpm:"libmodsecurity3-32bit~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3", rpm:"libmodsecurity3~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"modsecurity", rpm:"modsecurity~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"modsecurity-devel", rpm:"modsecurity-devel~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3-64bit", rpm:"libmodsecurity3-64bit~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmodsecurity3-32bit", rpm:"libmodsecurity3-32bit~3.0.10~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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
