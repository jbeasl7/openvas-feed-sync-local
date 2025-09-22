# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0392.1");
  script_cve_id("CVE-2012-0551", "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-1541", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1721", "CVE-2012-1722", "CVE-2012-1725", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3213", "CVE-2012-3216", "CVE-2012-3342", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5089", "CVE-2013-0169", "CVE-2013-0351", "CVE-2013-0401", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0438", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0450", "CVE-2013-0485", "CVE-2013-0809", "CVE-2013-1473", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481", "CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1491", "CVE-2013-1493", "CVE-2013-1500", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1563", "CVE-2013-1569", "CVE-2013-1571", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2435", "CVE-2013-2437", "CVE-2013-2440", "CVE-2013-2442", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2459", "CVE-2013-2463", "CVE-2013-2464", "CVE-2013-2465", "CVE-2013-2466", "CVE-2013-2468", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3009", "CVE-2013-3011", "CVE-2013-3012", "CVE-2013-3743", "CVE-2013-3829", "CVE-2013-4002", "CVE-2013-4041", "CVE-2013-5372", "CVE-2013-5375", "CVE-2013-5456", "CVE-2013-5457", "CVE-2013-5458", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5776", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5787", "CVE-2013-5788", "CVE-2013-5789", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5812", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5824", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843", "CVE-2013-5848", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5887", "CVE-2013-5888", "CVE-2013-5889", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899", "CVE-2013-5907", "CVE-2013-5910", "CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0387", "CVE-2014-0403", "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424", "CVE-2014-0428", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0449", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0878", "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2409", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2420", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2428", "CVE-2014-8891", "CVE-2014-8892", "CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0204", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0392-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0392-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150392-1.html");
  script_xref(name:"URL", value:"http://www.ibm.com/developerworks/java/jdk/alerts/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/592934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/778629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/785631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/788750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931702");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-February/001257.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'IBM Java 6' package(s) announced via the SUSE-SU-2015:0392-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IBM Java 6 SR15 has been released and fixes lots of bugs and security
issues.

More information can be found on:
[link moved to references]
<[link moved to references]>

Security Issue references:

 * CVE-2013-5458
 <[link moved to references]>
 * CVE-2013-5456
 <[link moved to references]>
 * CVE-2013-5457
 <[link moved to references]>
 * CVE-2013-4041
 <[link moved to references]>
 * CVE-2013-5375
 <[link moved to references]>
 * CVE-2013-5372
 <[link moved to references]>
 * CVE-2013-5843
 <[link moved to references]>
 * CVE-2013-5789
 <[link moved to references]>
 * CVE-2013-5830
 <[link moved to references]>
 * CVE-2013-5829
 <[link moved to references]>
 * CVE-2013-5787
 <[link moved to references]>
 * CVE-2013-5788
 <[link moved to references]>
 * CVE-2013-5824
 <[link moved to references]>
 * CVE-2013-5842
 <[link moved to references]>
 * CVE-2013-5782
 <[link moved to references]>
 * CVE-2013-5817
 <[link moved to references]>
 * CVE-2013-5809
 <[link moved to references]>
 * CVE-2013-5814
 <[link moved to references]>
 * CVE-2013-5832
 <[link moved to references]>
 * CVE-2013-5850
 <[link moved to references]>
 * CVE-2013-5838
 <[link moved to references]>
 * CVE-2013-5802
 <[link moved to references]>
 * CVE-2013-5812
 <[link moved to references]>
 * CVE-2013-5804
 <[link moved to references]>
 * CVE-2013-5783
 <[link moved to references]>
 * CVE-2013-3829
 <[link moved to references]>
 * CVE-2013-5823
 <[link moved to references]>
 * CVE-2013-5831
 <[link moved to references]>
 * CVE-2013-5820
 <[link moved to references]>
 * CVE-2013-5819
 <[link moved to references]>
 * CVE-2013-5818
 <[link moved to references]>
 * CVE-2013-5848
 <[link moved to references]>
 * CVE-2013-5776
 <[link moved to references]>
 * CVE-2013-5774
 <[link moved to references]>
 * CVE-2013-5825
 <[link moved to references]>
 * CVE-2013-5840
 <[link moved to references]>
 * CVE-2013-5801
 <[link moved to references]>
 * CVE-2013-5778
 <[link moved to references]>
 * CVE-2013-5851
 <[link moved to references]>
 * CVE-2013-5800
 <[link moved to references]>
 * CVE-2013-5784
 <[link moved to references]>
 * CVE-2013-5849
 <[link moved to references]>
 * CVE-2013-5790
 <[link moved to references]>
 * CVE-2013-5780
 <[link moved to references]>
 * CVE-2013-5797
 <[link moved to references]>
 * CVE-2013-5803
 <[link moved to references]>
 * CVE-2013-5772
 <[link moved to references]>");

  script_tag(name:"affected", value:"'IBM Java 6' package(s) on SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server for SAP Applications 11-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr16.2~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr16.0~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr16.2~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr16.2~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr16.2~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr15.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr15.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-devel", rpm:"java-1_6_0-ibm-devel~1.6.0_sr16.0~0.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr15.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr15.0~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr15.0~0.5.1", rls:"SLES11.0SP2"))) {
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
