# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03287.1");
  script_cve_id("CVE-2025-10527", "CVE-2025-10528", "CVE-2025-10529", "CVE-2025-10532", "CVE-2025-10533", "CVE-2025-10536", "CVE-2025-10537");
  script_tag(name:"creation_date", value:"2025-09-24 04:11:40 +0000 (Wed, 24 Sep 2025)");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03287-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503287-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249391");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041792.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:03287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Firefox Extended Support Release 140.3.0 ESR (bsc#1249391).

MFSA 2025-75:

 * CVE-2025-10527 (bmo#1984825)
 Sandbox escape due to use-after-free in the Graphics:
 Canvas2D component
 * CVE-2025-10528 (bmo#1986185)
 Sandbox escape due to undefined behavior, invalid pointer in
 the Graphics: Canvas2D component
 * CVE-2025-10529 (bmo#1970490)
 Same-origin policy bypass in the Layout component
 * CVE-2025-10532 (bmo#1979502)
 Incorrect boundary conditions in the JavaScript: GC component
 * CVE-2025-10533 (bmo#1980788)
 Integer overflow in the SVG component
 * CVE-2025-10536 (bmo#1981502)
 Information disclosure in the Networking: Cache component
 * CVE-2025-10537 (bmo#1938220, bmo#1980730, bmo#1981280,
 bmo#1981283, bmo#1984505, bmo#1985067)
 Memory safety bugs fixed in Firefox ESR 140.3, Thunderbird
 ESR 140.3, Firefox 143 and Thunderbird 143");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.3.0~112.279.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.3.0~112.279.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.3.0~112.279.1", rls:"SLES12.0SP5"))) {
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
