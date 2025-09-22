# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

function docker_build_all_containers_array( type )
{
  local_var type;
  local_var containers, _id, state, name, ports, image, co;

  if( ! type )
    type = 'lsc';

  containers =  get_kb_list( "docker/" + type + "/container/*/id" );

  if( ! containers ) return;

  foreach _id( containers )
  {
    state = get_kb_item( "docker/" + type + "/container/" + _id  + "/state" );
    name  = get_kb_item( "docker/" + type + "/container/" + _id  + "/name" );
    ports = get_kb_item( "docker/" + type + "/container/" + _id  + "/ports" );
    image = get_kb_item( "docker/" + type + "/container/" + _id  + "/image" );

    if( ! ports )
      ports = '';

    co[ _id ] = make_array( "name",  name,
                            "id",    _id,
                            "image", image,
                            "ports", ports );
  }

  return co;
}

function docker_build_running_containers_array( type )
{
  local_var type;
  local_var containers, _id, state, name, ports, image, co;

  if( ! type )
    type = 'lsc';

  containers =  get_kb_list( "docker/" + type + "/container/*/id" );

  if( ! containers ) return;

  foreach _id( containers )
  {
    state = get_kb_item( "docker/" + type + "/container/" + _id  + "/state" );

    if( state !~ "^Up " ) continue;

    name  = get_kb_item( "docker/" + type + "/container/" + _id  + "/name" );
    ports = get_kb_item( "docker/" + type + "/container/" + _id  + "/ports" );
    image = get_kb_item( "docker/" + type + "/container/" + _id  + "/image" );

    if( ! ports )
      ports = '';

    co[ _id ] = make_array( "name",  name,
                            "id",    _id,
                            "image", image,
                            "ports", ports );
  }

  return co;
}

function docker_get_running_containers( type )
{
  local_var type, ret_array;

  if( type )
    return docker_build_running_containers_array( type:type );

  ret_array = docker_get_running_containers( type:"lsc" );

  if( ! ret_array )
    ret_array = docker_get_running_containers( type:"remote" );

  return ret_array;

}

function docker_truncate_id( )
{
  v = _FCT_ANON_ARGS[0];

  if( ! v )
    return;

   return substr( v, 0, 11 );
}
