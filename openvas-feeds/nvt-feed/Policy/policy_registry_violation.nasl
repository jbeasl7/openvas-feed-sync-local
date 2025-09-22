# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105990");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-22 12:45:52 +0700 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Registry Check: Violations");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Policy");
  script_dependencies("Policy/policy_registry.nasl");
  script_mandatory_keys("policy/registry/started");

  script_tag(name:"summary", value:"List registry entries which didn't pass the registry
  policy check.");

  script_tag(name:"solution", value:"Update or reconfigure the affected service / system / host according to the
  policy requirement.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

violations = get_kb_list( "policy/registry/violation_list" );

if( violations ) {

  # Sort to not report changes on delta reports if just the order is different
  violations = sort( violations );

  report  = 'The following registry entries did not pass the registry policy check:\n\n';
  report += 'Registry entry | Present | Value checked against | Value set in registry\n';

  foreach violation( violations ) {
    report += violation + '\n';
  }

  security_message( port:0, data:report );
}

exit( 0 );
