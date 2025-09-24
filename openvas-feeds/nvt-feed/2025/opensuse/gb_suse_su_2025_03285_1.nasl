# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03285.1");
  script_cve_id("CVE-2025-53192");
  script_tag(name:"creation_date", value:"2025-09-23 04:07:22 +0000 (Tue, 23 Sep 2025)");
  script_version("2025-09-23T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-09-23 05:39:06 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03285-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03285-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503285-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248252");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041789.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mybatis, ognl' package(s) announced via the SUSE-SU-2025:03285-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mybatis, ognl fixes the following issues:

Version update to 3.5.7:

 * Bug fixes:

 + Improved performance under JDK 8. #2223

Version update to 3.5.8:

 * List of changes:

 + Avoid NullPointerException when mapping an empty string to
 java.lang.Character. #2368
 + Fixed an incorrect argument when initializing static object.
 This resolves a compatibility issue with quarkus-mybatis.
 #2284
 + Performance improvements. #2297 #2335 #2340

Version update to 3.5.9:

 * List of changes:

 + Add nullable to <foreach />. If enabled, it skips the
 iteration when the collection is null instead of throwing an
 exception. To enable this feature globally, set
 nullableOnForEach=true in the config. #1883

Version update to 3.5.10:

 * Bug fixes:

 + Unexpected illegal reflective access warning (or
 InaccessibleObjectException on Java 16+) when calling method
 in OGNL expression. #2392
 + IllegalAccessException when auto-mapping Records (JEP-359)
 #2195
 + 'interrupted' status is not set when
 PooledConnection#getConnection() is interrupted. #2503

 * Enhancements:

 + A new option argNameBasedConstructorAutoMapping is added. If
 enabled, constructor argument names are used to look up
 columns when auto-mapping. #2192
 + Added a new property skipSetAutoCommitOnClose to
 JdbcTransactionFactory. Skipping setAutoCommit() call could
 improve performance with some drivers. #2426
 + <idArg /> can now be listed after <arg /> in <constructor />.
 #2541

Version update to 3.5.11:

 * Bug fixes:

 + OGNL could throw IllegalArgumentException when invoking
 inherited method. #2609
 + returnInstanceForEmptyRow is not applied to constructor
 auto-mapping. #2665

Version update to 3.5.12

 * User impactful changes

 + #2703 Referencing collection parameter by name fails fixing
 #2693
 + #2709 Fix a race condition caused by other threads calling
 mapper methods while mapped tables are being constructed
 + #2727 Enable ability to provide custom configuration to
 XMLConfigBuilder
 + #2731 Adding mapper could fail under JPMS
 + #2741 Add 'affectedData' attribute to @select,
 @SelectProvider, and <select />
 + #2767 Resolve resultType by namespace and id when not
 provided resultType and resultMap
 + #2804 Search readable property when resolving constructor arg
 type by name
 + Minor correction: 'boolean' can never be null (primative)
 + General library updates
 + Uses parameters option for compiler now (needed by spring boot
 3) (for reflection needs)

 * Code cleanup

 + #2816 Use open rewrite to partially cleanup java code
 + #2817 Add private constructors per open rewrite
 + #2819 Add final where appropriate per open rewrite
 + #2825 Cleanup if statement breaks / return logic
 + #2826 Eclipse based cleanup

 * Build

 + #2820 Remove test ci group profile in favor of more direct
 usage on GH-Actions and update deprecated surefire along in
 overview in README.md
 + Adjustments to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mybatis, ognl' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"mybatis", rpm:"mybatis~3.5.19~150200.5.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mybatis-javadoc", rpm:"mybatis-javadoc~3.5.19~150200.5.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ognl", rpm:"ognl~3.4.7~150200.5.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ognl-javadoc", rpm:"ognl-javadoc~3.4.7~150200.5.3.1", rls:"openSUSELeap15.6"))) {
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
