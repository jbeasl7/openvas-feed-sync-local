# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2568.1");
  script_cve_id("CVE-2022-4065");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-26 03:24:55 +0000 (Sat, 26 Nov 2022)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2568-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2568-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242568-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205628");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/019004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mockito, snakeyaml, testng' package(s) announced via the SUSE-SU-2024:2568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mockito, snakeyaml, testng fixes the following issues:

mockito was updated to version 5.11.0:

- Added bundle manifest to the mockito-core artifact
- Mockito 5 is making core changes to ensure compatibility with future JDK versions.
- Switch the Default MockMaker to mockito-inline (not applicable to mockito-android)

 * Mockito 2.7.6 introduced the mockito-inline mockmaker based on the 'inline bytecode' principle, offering
 compatibility advantages over the subclass mockmaker
 * This change avoids JDK restrictions, such as violating module boundaries and leaking subclass creation

- Legitimate use cases for the subclass mockmaker:

 * Scenarios where the inline mockmaker does not function, such as on Graal VM's native image
 * If avoiding mocking final classes, the subclass mockmaker remains a viable option, although issues may arise on
 JDK 17+
 * Mockito aims to support both mockmakers, allowing users to choose based on their requirements.

- Update the Minimum Supported Java Version to 11

 * Mockito 5 raised the minimum supported Java version to 11
 * Community member @reta contributed to this change.
 * Users still on JDK 8 can continue using Mockito 4, with minimal API differences between versions

- New type() Method on ArgumentMatcher

 * The ArgumentMatcher interface now includes a new type() method to support varargs methods, addressing previous
 limitations
 * Users can now differentiate between matching calls with any exact number of arguments or match any number of
 arguments
 * Mockito 5 provides a default implementation of the new method, ensuring backward compatibility.
 * No obligation for users to implement the new method, Mockito 5 considers Void.type by default for varargs handling
 * ArgumentCaptor is now fully type-aware, enabling capturing specific subclasses on a generic method.

- byte-buddy does not bundle asm, but uses objectweb-asm as external library

snake-yaml was updated to version 2.2:

- Changes of version 2.2:

 * Define default scalar style as PLAIN (for polyglot Maven)
 * Add missing 'exports org.yaml.snakeyaml.inspector' to module-info.java

- Changes of version 2.1:

 * Heavy Allocation in Emitter.analyzeScalar(String) due to Regex Overhead
 * Use identity in toString() for sequences to avoid OutOfMemoryError
 * NumberFormatException from SnakeYAML due to int overflow for corrupt YAML version
 * Document size limit should be applied to single document notthe whole input stream
 * Detect invalid Unicode code point (thanks to Tatu Saloranta)
 * Remove Trusted*Inspector classes from main sources tree

- Changes of version 2.0:

 * Rollback to Java 7 target
 * Add module-info.java
 * Migrate to Java 8
 * Remove many deprecated constructors
 * Remove long deprecated methods in FlowStyle
 * Do not allow global tags by default
 * Yaml.LoadAs() signature to support Class<? super T> type instead of Class<T>
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mockito, snakeyaml, testng' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mockito", rpm:"mockito~5.11.0~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mockito-javadoc", rpm:"mockito-javadoc~5.11.0~150200.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snakeyaml", rpm:"snakeyaml~2.2~150200.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snakeyaml-javadoc", rpm:"snakeyaml-javadoc~2.2~150200.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testng", rpm:"testng~7.10.1~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testng-javadoc", rpm:"testng-javadoc~7.10.1~150200.3.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"mockito", rpm:"mockito~5.11.0~150200.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mockito-javadoc", rpm:"mockito-javadoc~5.11.0~150200.3.7.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snakeyaml", rpm:"snakeyaml~2.2~150200.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snakeyaml-javadoc", rpm:"snakeyaml-javadoc~2.2~150200.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testng", rpm:"testng~7.10.1~150200.3.10.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"testng-javadoc", rpm:"testng-javadoc~7.10.1~150200.3.10.1", rls:"openSUSELeap15.6"))) {
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
