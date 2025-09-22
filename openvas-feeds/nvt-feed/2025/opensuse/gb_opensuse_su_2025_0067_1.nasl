# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0067.1");
  script_cve_id("CVE-2022-21618", "CVE-2022-21619", "CVE-2022-21624", "CVE-2022-21626", "CVE-2022-21628", "CVE-2022-3676", "CVE-2022-39399", "CVE-2023-21835", "CVE-2023-21843", "CVE-2023-21930", "CVE-2023-21937", "CVE-2023-21938", "CVE-2023-21939", "CVE-2023-21954", "CVE-2023-21967", "CVE-2023-21968", "CVE-2023-22006", "CVE-2023-22025", "CVE-2023-22036", "CVE-2023-22041", "CVE-2023-22044", "CVE-2023-22045", "CVE-2023-22049", "CVE-2023-22081", "CVE-2023-25193", "CVE-2023-2597", "CVE-2023-5676", "CVE-2024-20918", "CVE-2024-20919", "CVE-2024-20921", "CVE-2024-20932", "CVE-2024-20945", "CVE-2024-20952", "CVE-2024-21011", "CVE-2024-21012", "CVE-2024-21068", "CVE-2024-21094", "CVE-2024-21131", "CVE-2024-21138", "CVE-2024-21140", "CVE-2024-21145", "CVE-2024-21147", "CVE-2024-21208", "CVE-2024-21210", "CVE-2024-21217", "CVE-2024-21235", "CVE-2025-21502");
  script_tag(name:"creation_date", value:"2025-02-21 04:06:31 +0000 (Fri, 21 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 21:32:32 +0000 (Tue, 30 May 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0067-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XA5CCGSPUXUTQHDG25O5DM4G37BLRUMN/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236804");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.35");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.36");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.38");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.40");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.41");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.43/");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.44/");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.46/");
  script_xref(name:"URL", value:"https://www.eclipse.org/openj9/docs/version0.49/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-17-openj9' package(s) announced via the openSUSE-SU-2025:0067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-17-openj9 fixes the following issues:

- Update to OpenJDK 17.0.14 with OpenJ9 0.49.0 virtual machine
- Including Oracle October 2024 and January 2025 CPU changes
 * CVE-2024-21208 (boo#1231702), CVE-2024-21210 (boo#1231711),
 CVE-2024-21217 (boo#1231716), CVE-2024-21235 (boo#1231719),
 CVE-2025-21502 (boo#1236278)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.12 with OpenJ9 0.46.0 virtual machine
- Including Oracle July 2024 CPU changes
 * CVE-2024-21131 (boo#1228046), CVE-2024-21138 (boo#1228047),
 CVE-2024-21140 (boo#1228048), CVE-2024-21147 (boo#1228052),
 CVE-2024-21145 (boo#1228051)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.11 with OpenJ9 0.44.0 virtual machine
- Including Oracle April 2024 CPU changes
 * CVE-2024-21012 (boo#1222987), CVE-2024-21094 (boo#1222986),
 CVE-2024-21011 (boo#1222979), CVE-2024-21068 (boo#1222983)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.10 with OpenJ9 0.43.0 virtual machine
- Including Oracle January 2024 CPU changes
 * CVE-2024-20918 (boo#1218907), CVE-2024-20919 (boo#1218903),
 CVE-2024-20921 (boo#1218905), CVE-2024-20932 (boo#1218908),
 CVE-2024-20945 (boo#1218909), CVE-2024-20952 (boo#1218911)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.9 with OpenJ9 0.41.0 virtual machine
- Including Oracle October 2023 CPU changes
 * CVE-2023-22081, boo#1216374
 * CVE-2023-22025, boo#1216339
- Including Openj9 0.41.0 fixes of CVE-2023-5676, boo#1217214
 * For other OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.8.1 with OpenJ9 0.40.0 virtual machine
 * JDK-8313765: Invalid CEN header (invalid zip64 extra data
 field size)

- Update to OpenJDK 17.0.8 with OpenJ9 0.40.0 virtual machine
- Including Oracle July 2023 CPU changes
 * CVE-2023-22006 (boo#1213473), CVE-2023-22036 (boo#1213474),
 CVE-2023-22041 (boo#1213475), CVE-2023-22044 (boo#1213479),
 CVE-2023-22045 (boo#1213481), CVE-2023-22049 (boo#1213482),
 CVE-2023-25193 (boo#1207922)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.7 with OpenJ9 0.38.0 virtual machine
- Including Oracle April 2023 CPU changes
 * CVE-2023-21930 (boo#1210628), CVE-2023-21937 (boo#1210631),
 CVE-2023-21938 (boo#1210632), CVE-2023-21939 (boo#1210634),
 CVE-2023-21954 (boo#1210635), CVE-2023-21967 (boo#1210636),
 CVE-2023-21968 (boo#1210637)
 * OpenJ9 specific vulnerability: CVE-2023-2597 (boo#1211615)
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.6 with OpenJ9 0.36.0 virtual machine
 * including Oracle January 2023 CPU changes
 + CVE-2023-21835, boo#1207246
 + CVE-2023-21843, boo#1207248
 * OpenJ9 changes, see
 [link moved to references]

- Update to OpenJDK 17.0.5 with OpenJ9 0.35.0 virtual machine
 * Including Oracle October 2022 CPU changes
 CVE-2022-21618 (boo#1204468), ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-17-openj9' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9", rpm:"java-17-openj9~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-demo", rpm:"java-17-openj9-demo~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-devel", rpm:"java-17-openj9-devel~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-headless", rpm:"java-17-openj9-headless~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-javadoc", rpm:"java-17-openj9-javadoc~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-jmods", rpm:"java-17-openj9-jmods~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-17-openj9-src", rpm:"java-17-openj9-src~17.0.14.0~bp156.3.3.1", rls:"openSUSELeap15.6"))) {
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
