# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0555.1");
  script_cve_id("CVE-2018-18074");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 04:18:49 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0555-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200555-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122668");
  script_xref(name:"URL", value:"https://github.com/nose-devs/nose2/blob/master/docs/changelog.rst");
  script_xref(name:"URL", value:"https://github.com/wolever/parameterized/issues/67");
  script_xref(name:"URL", value:"https://github.com/wolever/parameterized/pull/48");
  script_xref(name:"URL", value:"https://github.com/wolever/parameterized/pull/49");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-March/006561.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-aws-sam-translator, python-boto3, python-botocore, python-cfn-lint, python-jsonschema, python-nose2, python-parameterized, python-pathlib2, python-pytest-cov, python-requests, python-s3transfer' package(s) announced via the SUSE-SU-2020:0555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-aws-sam-translator, python-boto3, python-botocore, python-cfn-lint, python-jsonschema, python-nose2, python-parameterized, python-pathlib2, python-pytest-cov, python-requests, python-s3transfer, python-jsonpatch, python-jsonpointer, python-scandir, python-PyYAML fixes the following issues:

python-cfn-lint was included as a new package in 0.21.4.


python-aws-sam-translator was updated to 1.11.0:

 * Add ReservedConcurrentExecutions to globals
 * Fix ElasticsearchHttpPostPolicy resource reference
 * Support using AWS::Region in Ref and Sub
 * Documentation and examples updates
 * Add VersionDescription property to Serverless::Function
 * Update ServerlessRepoReadWriteAccessPolicy
 * Add additional template validation

Upgrade to 1.10.0:

 * Add GSIs to DynamoDBReadPolicy and DynamoDBCrudPolicy
 * Add DynamoDBReconfigurePolicy
 * Add CostExplorerReadOnlyPolicy and OrganizationsListAccountsPolicy
 * Add EKSDescribePolicy
 * Add SESBulkTemplatedCrudPolicy
 * Add FilterLogEventsPolicy
 * Add SSMParameterReadPolicy
 * Add SESEmailTemplateCrudPolicy
 * Add s3:PutObjectAcl to S3CrudPolicy
 * Add allow_credentials CORS option
 * Add support for AccessLogSetting and CanarySetting Serverless::Api properties
 * Add support for X-Ray in Serverless::Api
 * Add support for MinimumCompressionSize in Serverless::Api
 * Add Auth to Serverless::Api globals
 * Remove trailing slashes from APIGW permissions
 * Add SNS FilterPolicy and an example application
 * Add Enabled property to Serverless::Function event sources
 * Add support for PermissionsBoundary in Serverless::Function
 * Fix boto3 client initialization
 * Add PublicAccessBlockConfiguration property to S3 bucket resource
 * Make PAY_PER_REQUEST default mode for Serverless::SimpleTable
 * Add limited support for resolving intrinsics in Serverless::LayerVersion
 * SAM now uses Flake8
 * Add example application for S3 Events written in Go
 * Updated several example applications

- Initial build
 + Version 1.9.0
- Add patch to drop compatible releases operator from setup.py,
 required for SLES12 as the setuptools version is too old
 + ast_drop-compatible-releases-operator.patch


python-jsonschema was updated to 2.6.0:

* Improved performance on CPython by adding caching around ref resolution

Update to version 2.5.0:

* Improved performance on CPython by adding caching around ref
 resolution (#203)

Update to version 2.4.0:

* Added a CLI (#134)
* Added absolute path and absolute schema path to errors (#120)
* Added ``relevance``
* Meta-schemas are now loaded via ``pkgutil``
* Added ``by_relevance`` and ``best_match`` (#91)
* Fixed ``format`` to allow adding formats for non-strings (#125)
* Fixed the ``uri`` format to reject URI references (#131)

- Install /usr/bin/jsonschema with update-alternatives support

python-nose2 was updated to 0.9.1:

* the prof plugin now uses cProfile instead of hotshot for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-aws-sam-translator, python-boto3, python-botocore, python-cfn-lint, python-jsonschema, python-nose2, python-parameterized, python-pathlib2, python-pytest-cov, python-requests, python-s3transfer' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML", rpm:"python-PyYAML~5.1.2~26.9.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML-debuginfo", rpm:"python-PyYAML-debuginfo~5.1.2~26.9.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML-debugsource", rpm:"python-PyYAML-debugsource~5.1.2~26.9.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cfn-lint", rpm:"cfn-lint~0.21.4~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-boto3", rpm:"python-boto3~1.9.213~14.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-botocore", rpm:"python-botocore~1.12.213~28.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docutils", rpm:"python-docutils~0.15.2~3.4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-functools32", rpm:"python-functools32~3.2.3.2~2.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jsonpatch", rpm:"python-jsonpatch~1.1~10.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jsonpointer", rpm:"python-jsonpointer~1.0~10.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jsonschema", rpm:"python-jsonschema~2.6.0~5.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.20.1~8.7.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-s3transfer", rpm:"python-s3transfer~0.2.1~8.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-PyYAML", rpm:"python3-PyYAML~5.1.2~26.9.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aws-sam-translator", rpm:"python3-aws-sam-translator~1.11.0~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-boto3", rpm:"python3-boto3~1.9.213~14.9.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-botocore", rpm:"python3-botocore~1.12.213~28.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cfn-lint", rpm:"python3-cfn-lint~0.21.4~2.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docutils", rpm:"python3-docutils~0.15.2~3.4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jsonpatch", rpm:"python3-jsonpatch~1.1~10.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jsonpointer", rpm:"python3-jsonpointer~1.0~10.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jsonschema", rpm:"python3-jsonschema~2.6.0~5.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.20.1~8.7.7", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-s3transfer", rpm:"python3-s3transfer~0.2.1~8.3.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python-asn1crypto", rpm:"python-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-packaging", rpm:"python-packaging~17.1~2.5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyparsing", rpm:"python-pyparsing~2.2.0~7.6.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-asn1crypto", rpm:"python3-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-packaging", rpm:"python3-packaging~17.1~2.5.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyparsing", rpm:"python3-pyparsing~2.2.0~7.6.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python-asn1crypto", rpm:"python-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-packaging", rpm:"python-packaging~17.1~2.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyparsing", rpm:"python-pyparsing~2.2.0~7.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-asn1crypto", rpm:"python3-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-packaging", rpm:"python3-packaging~17.1~2.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyparsing", rpm:"python3-pyparsing~2.2.0~7.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML", rpm:"python-PyYAML~5.1.2~26.9.4", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-asn1crypto", rpm:"python-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-packaging", rpm:"python-packaging~17.1~2.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-PyYAML", rpm:"python3-PyYAML~5.1.2~26.9.4", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-asn1crypto", rpm:"python3-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-packaging", rpm:"python3-packaging~17.1~2.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML", rpm:"python-PyYAML~5.1.2~26.9.4", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-asn1crypto", rpm:"python-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-packaging", rpm:"python-packaging~17.1~2.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-asn1crypto", rpm:"python3-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-packaging", rpm:"python3-packaging~17.1~2.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python-PyYAML", rpm:"python-PyYAML~5.1.2~26.9.4", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-asn1crypto", rpm:"python-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-packaging", rpm:"python-packaging~17.1~2.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~2.20.1~8.7.7", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-asn1crypto", rpm:"python3-asn1crypto~0.24.0~2.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-packaging", rpm:"python3-packaging~17.1~2.5.1", rls:"SLES12.0SP5"))) {
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
