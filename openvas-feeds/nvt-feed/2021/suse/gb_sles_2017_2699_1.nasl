# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2699.1");
  script_cve_id("CVE-2012-6702", "CVE-2014-0191", "CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7187", "CVE-2014-7824", "CVE-2014-8964", "CVE-2014-9770", "CVE-2015-0245", "CVE-2015-1283", "CVE-2015-2059", "CVE-2015-2325", "CVE-2015-2327", "CVE-2015-2328", "CVE-2015-3210", "CVE-2015-3217", "CVE-2015-3238", "CVE-2015-3622", "CVE-2015-5073", "CVE-2015-5218", "CVE-2015-5276", "CVE-2015-7511", "CVE-2015-8380", "CVE-2015-8381", "CVE-2015-8382", "CVE-2015-8383", "CVE-2015-8384", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8387", "CVE-2015-8388", "CVE-2015-8389", "CVE-2015-8390", "CVE-2015-8391", "CVE-2015-8392", "CVE-2015-8393", "CVE-2015-8394", "CVE-2015-8395", "CVE-2015-8806", "CVE-2015-8842", "CVE-2015-8853", "CVE-2015-8948", "CVE-2016-0634", "CVE-2016-0718", "CVE-2016-0787", "CVE-2016-1234", "CVE-2016-1238", "CVE-2016-1283", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2037", "CVE-2016-2073", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-2381", "CVE-2016-3075", "CVE-2016-3191", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-3706", "CVE-2016-4008", "CVE-2016-4429", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449", "CVE-2016-4483", "CVE-2016-4574", "CVE-2016-4579", "CVE-2016-4658", "CVE-2016-5011", "CVE-2016-5300", "CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421", "CVE-2016-6185", "CVE-2016-6261", "CVE-2016-6262", "CVE-2016-6263", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-6313", "CVE-2016-6318", "CVE-2016-7141", "CVE-2016-7167", "CVE-2016-7543", "CVE-2016-7796", "CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624", "CVE-2016-9063", "CVE-2016-9318", "CVE-2016-9586", "CVE-2016-9597", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000366", "CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113", "CVE-2017-2616", "CVE-2017-6507", "CVE-2017-7407", "CVE-2017-7526", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050", "CVE-2017-9233");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-03 13:11:18 +0000 (Mon, 03 Jul 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2699-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172699-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SLES 12 Docker image' package(s) announced via the SUSE-SU-2017:2699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 12 container image has been updated to include security and stability fixes.
The following issues related to building of the container images have been fixed:
- Included krb5 package to avoid the inclusion of krb5-mini which gets
 selected as a dependency by the Build Service solver. (bsc#1056193)
- Do not install recommended packages when building container images.
 (bsc#975726)
A number of security issues that have been already fixed by updates released for SUSE Linux Enterprise Server 12 are now included in the base image. A package/CVE cross-reference is available below.
pam:
- CVE-2015-3238 libtasn1:
- CVE-2015-3622
- CVE-2016-4008 libidn:
- CVE-2015-2059
- CVE-2015-8948
- CVE-2016-6261
- CVE-2016-6262
- CVE-2016-6263 zlib:
- CVE-2016-9840
- CVE-2016-9841
- CVE-2016-9842
- CVE-2016-9843 curl:
- CVE-2016-5419
- CVE-2016-5420
- CVE-2016-5421
- CVE-2016-7141
- CVE-2016-7167
- CVE-2016-8615
- CVE-2016-8616
- CVE-2016-8617
- CVE-2016-8618
- CVE-2016-8619
- CVE-2016-8620
- CVE-2016-8621
- CVE-2016-8622
- CVE-2016-8623
- CVE-2016-8624
- CVE-2016-9586
- CVE-2017-1000100
- CVE-2017-1000101
- CVE-2017-7407 openssl:
- CVE-2016-2105
- CVE-2016-2106
- CVE-2016-2107
- CVE-2016-2108
- CVE-2016-2109
- CVE-2016-2177
- CVE-2016-2178
- CVE-2016-2179
- CVE-2016-2180
- CVE-2016-2181
- CVE-2016-2182
- CVE-2016-2183
- CVE-2016-6302
- CVE-2016-6303
- CVE-2016-6304
- CVE-2016-6306 libxml2:
- CVE-2014-0191
- CVE-2015-8806
- CVE-2016-1762
- CVE-2016-1833
- CVE-2016-1834
- CVE-2016-1835
- CVE-2016-1837
- CVE-2016-1838
- CVE-2016-1839
- CVE-2016-1840
- CVE-2016-2073
- CVE-2016-3627
- CVE-2016-3705
- CVE-2016-4447
- CVE-2016-4448
- CVE-2016-4449
- CVE-2016-4483
- CVE-2016-4658
- CVE-2016-9318
- CVE-2016-9597
- CVE-2017-9047
- CVE-2017-9048
- CVE-2017-9049
- CVE-2017-9050 util-linux:
- CVE-2015-5218
- CVE-2016-5011
- CVE-2017-2616 cracklib:
- CVE-2016-6318 systemd:
- CVE-2014-9770
- CVE-2015-8842
- CVE-2016-7796 pcre:
- CVE-2014-8964
- CVE-2015-2325
- CVE-2015-2327
- CVE-2015-2328
- CVE-2015-3210
- CVE-2015-3217
- CVE-2015-5073
- CVE-2015-8380
- CVE-2015-8381
- CVE-2015-8382
- CVE-2015-8383
- CVE-2015-8384
- CVE-2015-8385
- CVE-2015-8386
- CVE-2015-8387
- CVE-2015-8388
- CVE-2015-8389
- CVE-2015-8390
- CVE-2015-8391
- CVE-2015-8392
- CVE-2015-8393
- CVE-2015-8394
- CVE-2015-8395
- CVE-2016-1283
- CVE-2016-3191 appamor:
- CVE-2017-6507 bash:
- CVE-2014-6277
- CVE-2014-6278
- CVE-2016-0634
- CVE-2016-7543 cpio:
- CVE-2016-2037 glibc:
- CVE-2016-1234
- CVE-2016-3075
- CVE-2016-3706
- CVE-2016-4429
- CVE-2017-1000366 perl:
- CVE-2015-8853
- CVE-2016-1238
- CVE-2016-2381
- CVE-2016-6185 libssh2_org:
- CVE-2016-0787 expat:
- CVE-2012-6702
- CVE-2015-1283
- CVE-2016-0718
- CVE-2016-5300
- CVE-2016-9063
- CVE-2017-9233 ncurses:
- CVE-2017-10684
- CVE-2017-10685
- CVE-2017-11112
- CVE-2017-11113 libksba:
- CVE-2016-4574
- CVE-2016-4579 libgcrypt:
- CVE-2015-7511
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'SLES 12 Docker image' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"sles12-docker-image", rpm:"sles12-docker-image~1.1.4~20171002", rls:"SLES12.0"))) {
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
