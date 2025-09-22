# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1932.1");
  script_cve_id("CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513");
  script_tag(name:"creation_date", value:"2021-06-11 02:15:39 +0000 (Fri, 11 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 18:46:07 +0000 (Thu, 01 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1932-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1932-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211932-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179839");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/332689");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338848");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/613537");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/637780");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-June/008980.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/core/7th-gen-core-family-spec-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/xeon-e3-1200v6-spec-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/xeon-e5-v3-spec-update.html?wapkw=processor+spec+update+e5");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/xeon-e7-v3-spec-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/core/10th-gen-core-families-specification-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/core/8th-gen-core-spec-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/xeon/xeon-d-1500-specification-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/products/docs/processors/xeon/xeon-e-2100-specification-update.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00442.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00464.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00465.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2021:1932-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

- Updated to Intel CPU Microcode 20210525 release.

 - CVE-2020-24513: A domain bypass transient execution vulnerability was discovered on some Intel Atom processors that use a micro-architectural incident channel. (INTEL-SA-00465 bsc#1179833)

 See also: [link moved to references]

 - CVE-2020-24511: The IBRS feature to mitigate Spectre variant 2 transient execution side channel vulnerabilities may not fully prevent non-root (guest) branches from controlling the branch predictions of the root (host) (INTEL-SA-00464 bsc#1179836)

 See also [link moved to references])

 - CVE-2020-24512: Fixed trivial data value cache-lines such as all-zero value cache-lines may lead to changes in cache-allocation or write-back behavior for such cache-lines (bsc#1179837 INTEL-SA-00464)

 See also [link moved to references])

 - CVE-2020-24489: Fixed Intel VT-d device pass through potential local privilege escalation (INTEL-SA-00442 bsc#1179839)

 See also [link moved to references]

Other fixes:

- Update for functional issues. Refer to [Third Generation Intel Xeon Processor Scalable Family Specification Update]([link moved to references])for details.
- Update for functional issues. Refer to [Second Generation Intel Xeon Processor Scalable Family Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon Processor Scalable Family Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon Processor D-1500, D-1500 NS and D-1600 NS Spec Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon E7-8800 and E7-4800 v3 Processor Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon Processor E5 v3 Product Family Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [10th Gen Intel Core Processor Families Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [8th and 9th Gen Intel Core Processor Family Spec Update]([link moved to references]) for details.
- Update for functional issues. Refer to [7th Gen and 8th Gen (U Quad-Core) Intel Processor Families Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [6th Gen Intel Processor Family Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon E3-1200 v6 Processor Family Specification Update]([link moved to references]) for details.
- Update for functional issues. Refer to [Intel Xeon E-2100 and E-2200 Processor Family Specification Update]([link moved to references]) for details.

- New platforms:

<pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20210525~3.203.1", rls:"SLES15.0SP1"))) {
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
