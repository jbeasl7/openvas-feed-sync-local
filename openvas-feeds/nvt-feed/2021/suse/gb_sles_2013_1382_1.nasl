# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1382.1");
  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1706", "CVE-2013-1707", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1382-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1382-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131382-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2013:1382-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to Firefox 17.0.8esr (bnc#833389) to address:

 * MFSA 2013-63/CVE-2013-1701/CVE-2013-1702 (bmo#855331,
bmo#844088, bmo#858060, bmo#870200, bmo#874974, bmo#861530,
bmo#854157, bmo#893684, bmo#878703, bmo#862185, bmo#879139,
bmo#888107, bmo#880734) Miscellaneous memory safety hazards
(rv:23.0 / rv:17.0.8)
 * MFSA 2013-66/CVE-2013-1706/CVE-2013-1707 (bmo#888314,
bmo#888361) Buffer overflow in Mozilla Maintenance Service and Mozilla Updater
 * MFSA 2013-68/CVE-2013-1709 (bmo#848253) Document URI misrepresentation and masquerading
 * MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests allow for code execution and XSS attacks
 * MFSA 2013-71/CVE-2013-1712 (bmo#859072) Further Privilege escalation through Mozilla Updater
 * MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal used for validating URI for some Javascript components
 * MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin bypass with web workers and XMLHttpRequest
 * MFSA 2013-75/CVE-2013-1717 (bmo#406541) Local Java applets may read contents of local file system

Security Issue references:

 * CVE-2013-1701
>
 * CVE-2013-1702
>
 * CVE-2013-1706
>
 * CVE-2013-1707
>
 * CVE-2013-1709
>
 * CVE-2013-1710
>
 * CVE-2013-1712
>
 * CVE-2013-1713
>
 * CVE-2013-1714
>
 * CVE-2013-1717
>");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~17.0.8esr~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~17.0.8esr~0.5.1", rls:"SLES10.0SP4"))) {
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
